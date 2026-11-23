# 豆包工作（DoubaoWork）接入设计文档

本文档详细说明在 CheckinBox-Tools 中新增「豆包工作」（DoubaoWork）AI 客户端支持的完整技术方案，包括账号发现与导入、每日自动签到、额度与权益查询、客户端换号切换，以及前端界面与赛博金蛋集成。

---

## 1. 架构与目标

### 1.1 平台标识与基本属性
- **Provider ID**: `doubaowork`
- **Display Name**: `豆包工作`
- **品牌主色**: `#0057FF`（豆包蓝）/ `#2563EB`
- **官方文档/主页**: `https://www.doubao.com`
- **客户端架构**: 字节自研 `aha` 框架（Chromium 147+ 内核，支持 Multi-Profile）
- **客户端路径**:
  - `%LOCALAPPDATA%\Doubao\Application\Doubao.exe` 或 `%LOCALAPPDATA%\DoubaoWork\Application\DoubaoWork.exe`
  - 数据目录: `%LOCALAPPDATA%\Doubao\User Data` 或 `%LOCALAPPDATA%\DoubaoWork\User Data`

### 1.2 核心功能矩阵
| 功能 | 支持情况 | 实现说明 |
|---|---|---|
| **从本机导入** | ✅ 支持 | 读取 `Local State` 的 `profile.info_cache`，DPAPI 解密 Cookies 提取 `sessionid`、`sessionid_ss` 等 |
| **浏览器授权登录** | ✅ 支持 | 启动独立会话浏览器打开 `https://www.doubao.com/chat/`，扫码/手机号登录后捕获 Cookies |
| **每日签到** | ✅ 支持 | 调取 `/alice/ug/campaign/item/reward/claim/` 或 `/alice/ug/campaign/landing/checkin` 领取每日额度 |
| **额度查询** | ✅ 支持 | 调取 `/alice/commerce/sale/subscription/overview/`，展示套餐、5小时/近7天/每月限额及百分比 |
| **客户端换号** | ✅ 支持 | 优雅退出客户端，更新 `Local State` 的 `last_used` 并带 `--profile-directory` 参数重新拉起客户端 |
| **赛博金蛋** | ✅ 支持 | 首页与启动封面孵化舱增加豆包工作金蛋卡片 |

---

## 2. 后端适配器设计（Rust / src-tauri）

### 2.1 数据结构定义
```rust
/// 豆包工作账号凭据存储结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubaoCredential {
    /// 包含 sessionid、sessionid_ss 等 cookie 字符串
    pub cookie_header: String,
    /// 绑定的客户端 Profile 目录（如 "Profile 4"、"Default" 等），若是浏览器单独登录则为 None
    pub profile_dir: Option<String>,
    pub user_id: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub device_id: Option<String>,
    pub web_id: Option<String>,
}
```

### 2.2 本机导入流程（`discover`）
1. 探测客户端 `User Data` 目录（优先 `%LOCALAPPDATA%\Doubao\User Data`，次选 `%LOCALAPPDATA%\DoubaoWork\User Data`）。
2. 读取并解析 `<User Data>/Local State`（JSON 格式）：
   - 从 `os_crypt.encrypted_key` 提取 base64 数据，去掉前 5 字节（`DPAPI`），通过 `CryptUnprotectData` 解密获得 32 字节 AES 密钥。
   - 解析 `profile.info_cache`，遍历所有 Profile（`Default`、`Profile 2`、`Profile 3` 等）。
3. 针对每个 Profile：
   - 提取 `saman.user_id`（纯数字字符串）和用户名/昵称（`name` / `user_name`）。
   - 复制 `<User Data>/<Profile>/Network/Cookies` 到临时位置，读取 SQLite 中的 `doubao.com` cookies。
   - 用 AES-256-GCM 解密 `encrypted_value`（跳过前 3 字节 `v10`，取 12 字节 Nonce），拼接出有效的 Cookie Header。
4. 返回 `Vec<(Account, Value)>`，每个账号的 `origin` 标记为 `本机豆包工作 (<Profile>)`。

### 2.3 浏览器授权登录流程（`begin_authorization` / `poll_authorization`）
1. 用户点击“添加账号”时，分配独立的临时 `--user-data-dir` 目录。
2. 启动系统默认的 Chrome 或 Edge（带 `--remote-debugging-pipe`），打开 `https://www.doubao.com/chat/`。
3. 轮询目标页面的 Cookies，若检测到有效的 `sessionid` / `sessionid_ss`：
   - 调用 `https://www.doubao.com/passport/account/info/v2/` 换取真实用户 ID 与昵称。
   - 组装账号信息并完成导入，随后关闭并清理临时浏览器会话。

### 2.4 签到与额度接口
1. **状态检查（`check_status`）**：
   - 调用 `POST https://www.doubao.com/alice/user/launch` 获取 `campaign_group_code`（默认 `pc_incentive_task_mvp_v3`）。
   - 调用 `POST https://www.doubao.com/alice/ug/campaign/v3/detail/` 查询活动详情：
     - 检查 `tasks` 数组中 `campaign_code == "daily_signin"` 的任务状态：
       - `task_status == 3`: 已签到 (`ClaimState::Claimed`)
       - `task_status == 1`: 今日可签 (`ClaimState::Claimable`)，奖励额度通常为 200 或 400（活动期间双倍）
2. **签到执行（`claim`）**：
   - 优先调用桌面端领取接口 `POST https://www.doubao.com/alice/ug/campaign/item/reward/claim/`，带客户端特征头及 URL 查询参数：
     - `aid: '1044603', real_aid: '1044603', version_code: '20800', pc_version: '2.33.5'` 等；
     - 携带任务 ID 或 `{ campaign_group_code, campaign_item_code }`；
   - 重新请求 `detail` 接口复核：若 `task_status == 3` 或累计额度增加，判定签到成功；
   - 若遇到业务错误码（如 `710010702` 未开放），如实返回待重试状态，绝不谎报成功。
3. **额度查询（`get_quota`）**：
   - 调用 `POST https://www.doubao.com/alice/commerce/sale/subscription/overview/`（body: `{"product_line":"membership"}`）。
   - 解析套餐名称（`membership_display_name`）与时间窗口限制（5 小时使用率、近 7 天额度、每月限额与奖励额度）。

### 2.5 客户端换号（`client_switch.rs`）
1. **当前登录态识别（`detect_doubaowork`）**：
   - 读取 `<User Data>/Local State` 中的 `profile.last_used`；
   - 根据 `info_cache` 中该 profile 的 `saman.user_id` 匹配当前生效的账号。
2. **换号执行（`switch`）**：
   - 优雅关闭所有正在运行的 `Doubao.exe` / `DoubaoWork.exe` 进程，等待其退出。
   - 将 `Local State` 的 `profile.last_used` 写为目标账号对应的 `profile_dir`（如 `"Profile 2"`）。
   - 启动客户端：`Doubao.exe --profile-directory="<Profile>"`。

---

## 3. 前端集成（React / TypeScript）

1. **类型扩展（`src/lib/types.ts`）**：
   - 在平台常量联合类型中加入 `'doubaowork'`。
2. **图标与样式（`src/lib/agentIcons.ts`）**：
   - 添加豆包专属色彩配置与 SVG / PNG 图标映射。
3. **赛博金蛋（`LaunchScreen.tsx`）**：
   - 自动在首页“孵化舱”与平台侧栏呈现“豆包工作”卡片。
4. **额度格式化（`src/lib/credits.ts` / `welfare.ts`）**：
   - 适配豆包工作的 5 小时/7 天/每月多维额度展示。

---

## 4. 实施阶段计划

- **阶段 1：核心 Provider 逻辑实现**
  - 新建 `src-tauri/src/providers/doubaowork.rs`，实现本地 Profile 解析、DPAPI Cookies 解密、HTTP API 封装。
  - 注册到 `src-tauri/src/providers/mod.rs` 与 `src-tauri/src/commands.rs`。
- **阶段 2：换号与客户端管理**
  - 在 `launcher.rs` 添加豆包进程探测与定位。
  - 在 `client_switch.rs` 中支持 `detect_doubaowork` 与 `switch_doubaowork`。
- **阶段 3：前端界面与样式适配**
  - 添加平台配置、图标、额度展示逻辑。
- **阶段 4：测试与真实验证**
  - 编写 Rust 单元测试并执行；
  - 运行本机真实数据测试（读取已安装的豆包 4 个 Profile 并验证查询状态）；
  - 执行 `npm run tauri:dev` / `cargo test` 确认全绿。
