//! 切换客户端实际登录的账号。
//!
//! 做法借鉴 Cockpit Tools：客户端把自己的登录态存在一个本地文件里，
//! 所谓「换账号」就是 **备份当前凭据 → 写入目标账号的凭据 → 启动客户端**，
//! 客户端启动后读到新凭据，等于换了个账号登录。
//!
//! Cockpit 在 `~/.codex/.cockpit_codex_auth.json` 里记了「这个客户端的凭据
//! 现在属于哪个账号」，并配了 `.cockpit-token-locks` 防止并发写坏 ——
//! 我们这边每次切换前会先把客户端原来的登录态备份成 `<file>.bak`，可回滚。
//!
//! **支持范围**：
//!   * 妙手 `~/.meituan-catpaw/auth.json` —— 明文，结构简单；本地数据还按 uid 分目录
//!   * MiniMax `~/.minimax/auth/<env>/<region>/<clientId>/auth.json` —— 明文 JSON
//!   * Qoder CN `%APPDATA%\com.qodercn.app.stable\auth.v1.dat` —— Electron
//!     safeStorage 加密（`v10` + AES-256-GCM，密钥在 `Local State` 里由 DPAPI
//!     保护）。实测同一 Windows 用户可以解出密钥，也就能重新加密写回，
//!     详见 `core/os_crypt.rs`。
//!   * WorkBuddy（腾讯 CodeBuddy CN 桌面端）5.6+ 登录态在共享 auth 文件
//!     `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info`
//!     （敏感字段带官方 AES-256-GCM 信封 `$wbEncrypted`，详见 `core/wb_session.rs`）。
//!     5.6 之前的老客户端读 `%APPDATA%\WorkBuddy\User\globalStorage\state.vscdb`
//!     的 secret 键（safeStorage 密文），没有共享 auth 文件时才走这条老路
//!     （参考 Cockpit 对 codebuddy_cn 的注入做法）。
//!
//! ⚠️ 这会改写客户端的登录凭据。客户端在运行时**先自动关闭再写入**
//!（`switch` 入口统一处理：优雅关闭 → 超时强制结束 → 写入 → 重启，
//! 借鉴 Cockpit 的关闭→写入→重启一条龙），全程不需要用户手动退出客户端。
//!
//! **聊天记录同步**（`core/chat_sync.rs`，借鉴 Cockpit 的
//! `share_sessions_on_switch`）：WorkBuddy 开启开关后、Qoder 无论开关状态都会在
//! **关客户端之后、写凭据之前**把本地会话记录带给目标账号 —— WorkBuddy 5.x
//! 更新 `workbuddy.db` 的活动会话 `user_id`（并兼容旧版目录合并）；Qoder 继续共享本机历史，
//! 并将旧版切号流程留下的会话表合并恢复到当前数据库。
//! 同步失败不阻塞换号本身，结果
//! 如实带在 `SwitchOutcome::chat_sync` 里。MiniMax 的会话在服务端自动同步，
//! 永远不走这条路径。

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

use super::chat_sync::{self, ChatSyncReport};
use super::os_crypt;
use crate::core::paths::atomic_write;
use crate::providers::qoder::account_id as qoder_account_id;

/// 客户端当前实际登录的账号。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedAccount {
    pub account_id: String,
    pub label: String,
}

/// 一次切换的结果。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchOutcome {
    /// 客户端原登录态的备份路径（可回滚）
    pub backup: Option<String>,
    /// 写入的目标凭据文件
    pub target_file: String,
    /// 启动的客户端
    pub client_exe: String,
    /// 聊天记录同步结果（开关没开 = None；同步失败也在里面如实报告）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_sync: Option<ChatSyncReport>,
}

/// 这个平台能不能靠「写凭据文件」来切账号。
pub fn is_switchable(provider: &str) -> bool {
    matches!(
        provider,
        "minimax" | "miaoshou" | "qoder" | "workbuddy" | "trae" | "doubaowork"
    )
}

/// 读客户端当前登录的是哪个账号（只读，不改任何东西）。
pub fn detect(provider: &str) -> Result<Option<DetectedAccount>> {
    match provider {
        "minimax" => detect_minimax(),
        "miaoshou" => detect_miaoshou(),
        "qoder" => Ok(detect_qoder()),
        "workbuddy" => Ok(detect_workbuddy()),
        "trae" => Ok(detect_trae()),
        "doubaowork" => Ok(detect_doubaowork()),
        _ => Ok(None),
    }
}

/// 切换客户端登录的账号 —— **第一步：关闭客户端**。
///
/// 写凭据之前必须等客户端**完全退出**：它退出时会把内存里的登录态写回文件，
/// 进程还活着就写会被它覆盖（这是换号失败最常见的姿势）。
///
/// ⚠️ 调用方在本函数返回后、`finish_switch` 之前，必须先**捕获客户端当前
/// 登录的账号**（`commands.rs::capture_client_login`）。捕获放在关客户端
/// **之后**是刻意的：客户端会按自己的节奏刷新 token（MiniMax 约每小时一次，
/// 每次刷新都**轮换 refresh token**）—— 先捕获再关，捕获到的 RT 可能在
/// 关闭前就被客户端轮换掉，写进文件的就是死凭据，客户端启动刷新
/// `invalid_grant` 后会**删掉凭据**退回登录页（2026-11-05 实测：捕获后
/// 2 秒客户端刷新，切换写入的 RT 已废，用户被迫重新录入账号）。
pub fn begin_switch(provider: &str) -> Result<()> {
    if crate::core::launcher::is_running(provider) && !crate::core::launcher::close_client(provider)
    {
        return Err(anyhow!(
            "客户端正在运行且无法自动关闭（可能权限不足）：请手动退出后重试"
        ));
    }
    Ok(())
}

/// 切换客户端登录的账号 —— **第二步：同步聊天记录 → 写凭据 → 启动**。
///
/// 调用前必须先 `begin_switch` 关掉客户端，并已捕获过客户端当前登录的账号。
/// 客户端退出后文件里就是它最后一次提交的登录态，写凭据不会被覆盖。
///
/// `chat_sync_enabled` 是该 agent 的「同步聊天记录」开关：开着且平台支持时，
/// 在写凭据**之前**把本地会话记录带给目标账号（来源账号在客户端退出后、
/// 覆盖凭据前识别）。聊天同步失败**不阻塞**换号本身，结果如实上报。
pub fn finish_switch(
    provider: &str,
    cred: &Value,
    account_id: &str,
    label: &str,
    chat_sync_enabled: bool,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    // 切换期间客户端又被打开了（用户手动/其他工具）：顶着运行中的客户端写
    // 会被它的退出回写覆盖，直接拒绝
    if crate::core::launcher::is_running(provider) {
        return Err(anyhow!("客户端在切换期间被重新打开，请重试"));
    }

    let chat_target_id = if provider == "workbuddy" {
        // 旧版导入的池内 ID 可能是 token 指纹，WorkBuddy 的聊天只认客户端 UID。
        cred["uid"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("账号凭据里没有 uid，无法写入 WorkBuddy 登录态"))?
    } else {
        account_id
    };

    // 来源账号必须在覆盖凭据**之前**识别（写完凭据文件，detect 读到的就是
    // 目标账号了）。识别失败 = 聊天记录无法归属，跳过同步（不动数据）。
    let chat_from = if chat_sync_enabled && chat_sync::supports(provider) {
        detect(provider).ok().flatten().map(|d| d.account_id)
    } else {
        None
    };

    // 聊天同步放在写凭据之前（与上游 Cockpit 的 prepare_account_switch 同序）；
    // 失败只记录、不阻塞换号 —— 换号是主功能，聊天同步是增强。
    let chat_sync_source: Option<Option<&str>> = if provider == "qoder" {
        Some(None)
    } else {
        chat_from.as_deref().map(Some)
    };
    let chat_sync_report = match chat_sync_source {
        Some(from) => {
            on_progress("syncing");
            match chat_sync::sync_on_switch(provider, from, chat_target_id) {
                Ok(report) => Some(report),
                Err(e) => {
                    let entry = crate::core::logging::LogEntry::new(
                        provider,
                        account_id,
                        label,
                        "failed",
                        0,
                        format!("聊天记录同步失败（不影响换号）：{e}"),
                    );
                    let _ = crate::core::logging::append(&entry);
                    Some(ChatSyncReport {
                        action: "failed".into(),
                        detail: format!("聊天记录同步失败（换号本身已完成）：{e}"),
                        ..Default::default()
                    })
                }
            }
        }
        None => None,
    };

    if chat_sync_enabled && chat_sync::supports(provider) && chat_from.is_none() {
        on_progress("syncSkipped");
    }
    on_progress("writing");
    let outcome = match provider {
        "minimax" => switch_minimax(cred, account_id, label, on_progress)?,
        "miaoshou" => switch_miaoshou(cred, account_id, label, on_progress)?,
        "qoder" => switch_qoder(cred, account_id, label, on_progress)?,
        "workbuddy" => switch_workbuddy(cred, account_id, label, on_progress)?,
        "trae" => switch_trae(cred, account_id, label, on_progress)?,
        "doubaowork" => switch_doubaowork(cred, account_id, label, on_progress)?,
        other => return Err(anyhow!("{other} 不支持切换客户端账号")),
    };
    Ok(SwitchOutcome {
        chat_sync: chat_sync_report,
        ..outcome
    })
}

// ---------------------------------------------------------------------------
// MiniMax Code
// ---------------------------------------------------------------------------

/// 递归找 MiniMax 的登录态文件（层级随版本变，不写死）。
fn minimax_auth_file() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let root = home.join(".minimax").join("auth");
    let mut out = Vec::new();
    collect(&root, &mut out, 0);
    out.into_iter().next()
}

fn collect(dir: &PathBuf, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 4 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out, depth + 1);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("auth.json") {
            out.push(path);
        }
    }
}

/// MiniMax Code 的记录键（**设备级**，换号登录不变）。
///
/// 键不是随机生成的 —— 客户端 app.asar 的 `namespace.js` 里是算出来的：
/// ```text
/// service = `com.minimax.mcode.oauth.{buildEnv}.{region}`
/// account = base64url(sha256(`{authHome}\0mcode-public`))
/// 记录键   = `{service}\0{account}`        （file-store.js 的 recordKey）
/// ```
/// 所以键**可以自己算出来**，不必等客户端先登录过一次：客户端从没登录成功时
/// auth.json 的 records 是空的（2026-11-02 实测：客户端卡在 authorizing 中途，
/// 把 records 清空了），硬找键就把换号卡成死路。
fn minimax_record_key(auth_home: &Path, build_env: &str, region: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let account = B64URL.encode(Sha256::digest(
        format!("{}\u{0}mcode-public", auth_home.to_string_lossy()).as_bytes(),
    ));
    format!("com.minimax.mcode.oauth.{build_env}.{region}\u{0}{account}")
}

/// 从登录态文件路径反推命名空间：`<authHome>/<buildEnv>/<region>/mcode-public/auth.json`。
fn minimax_namespace(path: &Path) -> Option<(PathBuf, String, String)> {
    let client_dir = path.parent()?; // mcode-public
    let region_dir = client_dir.parent()?; // cn
    let env_dir = region_dir.parent()?; // prod
    let auth_home = env_dir.parent()?; // auth
    Some((
        auth_home.to_path_buf(),
        env_dir.file_name()?.to_string_lossy().to_string(),
        region_dir.file_name()?.to_string_lossy().to_string(),
    ))
}

/// 客户端真实用过的记录键：登录态文件里的 + 备份文件里的。
///
/// 客户端登录成功时写下的键最权威；它中途重新登录、把 records 清空时，
/// 备份文件里的键就是它之前真正用的那个（切号时用它接着写）。
fn minimax_known_record_keys(path: &Path) -> Vec<String> {
    let mut files = vec![path.to_path_buf()];
    for suffix in ["bak", "cockpit.bak"] {
        files.push(path.with_file_name(format!("auth.json.{suffix}")));
    }
    // 多代备份里的登录态文件：客户端中途清空 records 时，
    // 备份里那份就是它之前真正用过的键（2026-11-02 实测踩坑）。
    files.extend(super::client_backup::stored_login_state_files("minimax"));
    let mut with_token: Vec<String> = Vec::new();
    let mut without_token: Vec<String> = Vec::new();
    for file in files {
        let Ok(raw) = std::fs::read_to_string(&file) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(records) = parsed["records"].as_object() else {
            continue;
        };
        for (key, rec) in records {
            let bucket = if rec["accessToken"]
                .as_str()
                .map(|t| !t.is_empty())
                .unwrap_or(false)
            {
                &mut with_token
            } else {
                &mut without_token
            };
            if !bucket.iter().any(|k| k == key) {
                bucket.push(key.clone());
            }
        }
    }
    with_token.into_iter().chain(without_token).collect()
}

/// 记录键是客户端生成的**设备级**键（`<clientId>\0<设备hash>`，换号登录不变）。
fn detect_minimax() -> Result<Option<DetectedAccount>> {
    let Some(path) = minimax_auth_file() else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path)?;
    let parsed: Value = serde_json::from_str(&raw)?;
    let Some(records) = parsed["records"].as_object() else {
        return Ok(None);
    };
    for key in records.keys() {
        if let Some(rec) = records.get(key) {
            if rec["accessToken"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
            {
                // 账号 id 用客户端配置里的 userID（**账号级**，换号会变）。
                // 记录键的 hash 是设备级的，换号后不变，不能当账号 id。
                let id = crate::providers::minimax::local_user_id()
                    .unwrap_or_else(|| key.rsplit('\u{0}').next().unwrap_or(key).to_string());
                return Ok(Some(DetectedAccount {
                    label: crate::providers::minimax::local_label(),
                    account_id: id,
                }));
            }
        }
    }
    Ok(None)
}

fn switch_minimax(
    cred: &Value,
    _account_id: &str,
    _label: &str,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    let path = minimax_switch_path(cred)?;

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| "{\"schemaVersion\":1,\"records\":{}}".into());
    let parsed: Value =
        serde_json::from_str(&raw).unwrap_or_else(|_| json!({"schemaVersion": 1, "records": {}}));

    let records = parsed["records"].as_object().cloned().unwrap_or_default();

    let state_path = path.with_file_name("auth-state.json");
    let state: Value = std::fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));

    // 命名空间（buildEnv / region）以路径为准，状态日记兜底
    let namespace = minimax_namespace(&path);
    let build_env = namespace
        .as_ref()
        .map(|(_, env, _)| env.clone())
        .or_else(|| state["buildEnv"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "prod".to_string());
    let region = namespace
        .as_ref()
        .map(|(_, _, r)| r.clone())
        .or_else(|| state["region"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "cn".to_string());
    let auth_home = namespace
        .as_ref()
        .map(|(home, _, _)| home.clone())
        .unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".minimax").join("auth"))
                .unwrap_or_default()
        });

    // 记录键是**设备级**的（换号登录键不变，只有 token 换）：客户端用过的键
    // 优先；它一个都没有（从没登录成功 / 登录到一半把 records 清了）就按客户端
    // 自己的命名空间公式推导 —— 键是算出来的，不必等它先登录一次。
    let known_keys = minimax_known_record_keys(&path);
    let target_key = match known_keys.first() {
        Some(key) => key.clone(),
        None => minimax_record_key(&auth_home, &build_env, &region),
    };

    // 凭据字段按客户端契约校验（app.asar 的 parseStoredCredential）：任何一项
    // 不合法，客户端会把整个 auth.json 判成损坏、退回重新登录。
    let (access, refresh) = crate::providers::minimax::switch_tokens(cred)?;
    let expires_at_ms = cred
        .get("expires_at_ms")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            anyhow!("目标账号缺少凭据有效期（expires_at_ms），写不进 MiniMax Code 登录态")
        })?;

    // 新代数取「状态日记 / 现有凭据」里的最大值 +1 —— 客户端的状态机要求
    // auth-state.json 和 auth.json 的 generation 严格一致，否则判会话不可信、弹重新登录
    let old_record = records.get(&target_key);
    let base_gen = state["generation"].as_i64().unwrap_or(0).max(
        old_record
            .and_then(|r| r["generation"].as_i64())
            .unwrap_or(0),
    );

    // 记录本体：按客户端契约逐项拼齐（不拿旧记录当模板 —— 旧记录可能缺字段）
    let mut record = json!({
        "schemaVersion": 1,
        "tokenType": "Bearer",
        "clientId": "mcode-public",
        "scopes": ["agent.default"],
        "audience": "agent-backend",
        "accessToken": access,
        "refreshToken": refresh,
        "expiresAtMs": expires_at_ms,
        "generation": base_gen + 1,
    });
    // 沿用旧记录里的可选字段（客户端写过的 loginEpoch 等，缺了不影响解析）
    if let Some(old) = old_record {
        for field in ["loginEpoch", "subject", "accountId"] {
            if let Some(v) = old
                .get(field)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                record[field] = Value::String(v.to_string());
            }
        }
    }

    // 只留目标账号那一条 —— 客户端是「取第一条非空 token」，留着别的会被它抢先
    let mut new_records = Map::new();
    new_records.insert(target_key, record);
    let mut out = parsed;
    out["records"] = Value::Object(new_records);
    if out.get("schemaVersion").is_none() {
        out["schemaVersion"] = json!(1);
    }

    // 凭据和状态日记要一起写、generation 一致：
    // 只写凭据不写状态的话，客户端的状态机会判定会话不可信，启动直接弹重新登录
    //（2026-10-24 实测踩坑：切换后客户端弹登录框，根因就是状态日记对不上）。
    // 状态日记里**不能留 authorization 租约**：那是客户端自己发起授权时的半成品
    //（status=authorizing），留着它客户端会接着去开那个已经过期的授权链接，
    // 登录态也就一直空着（2026-11-02 实测踩坑）。
    let mut new_state = json!({
        "schemaVersion": 2,
        "status": "authenticated",
        "storeKind": "file",
        "clientId": "mcode-public",
        "scopes": ["agent.default"],
        "audience": "agent-backend",
        "buildEnv": build_env,
        "region": region,
        "generation": base_gen + 1,
    });
    if expires_at_ms > 0 {
        new_state["expiresAtMs"] = json!(expires_at_ms);
    }

    // 备份成组：auth.json 与 auth-state.json 必须同一代，缺一半回滚会让
    // 客户端状态机判定会话不可信（generation 对不上 → 客户端弹登录框）。
    // 备份失败不阻断换号 —— 换号本身不依赖备份成功。
    let backup = match super::client_backup::backup_client_login(
        "minimax",
        &[
            (path.clone(), "auth.json".to_string()),
            (state_path.clone(), "auth-state.json".to_string()),
        ],
        "switch",
    ) {
        Ok(b) => Some(b.dir),
        Err(err) => {
            eprintln!("备份客户端登录态失败（不影响本次切换）：{err}");
            None
        }
    };
    atomic_write(&path, serde_json::to_string_pretty(&out)?.as_bytes())?;
    atomic_write(
        &state_path,
        serde_json::to_string_pretty(&new_state)?.as_bytes(),
    )?;

    on_progress("launching");
    let client_exe = crate::core::launcher::launch("minimax")
        .map_err(|e| anyhow!("凭据已写入客户端登录态，但客户端启动失败：{e}"))?;
    Ok(SwitchOutcome {
        backup,
        target_file: path.to_string_lossy().to_string(),
        client_exe: client_exe.to_string_lossy().to_string(),
        chat_sync: None,
    })
}

pub(crate) fn minimax_switch_path(cred: &Value) -> Result<PathBuf> {
    cred["auth_file"]
        .as_str()
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(minimax_auth_file)
        .ok_or_else(|| anyhow!("没找到 MiniMax Code 的登录态文件，请先启动客户端"))
}

// ---------------------------------------------------------------------------
// 妙手（美团 CatPaw）
// ---------------------------------------------------------------------------

fn miaoshou_auth_file() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let path = home.join(".meituan-catpaw").join("auth.json");
    path.is_file().then_some(path)
}

fn detect_miaoshou() -> Result<Option<DetectedAccount>> {
    let Some(path) = miaoshou_auth_file() else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path)?;
    let parsed: Value = serde_json::from_str(&raw)?;
    let uid = parsed["account"]["uid"].as_str().unwrap_or("");
    if uid.is_empty() {
        return Ok(None);
    }
    let label = parsed["account"]["name"]
        .as_str()
        .or_else(|| parsed["account"]["loginName"].as_str())
        .unwrap_or("")
        .to_string();
    Ok(Some(DetectedAccount {
        account_id: uid.to_string(),
        label,
    }))
}

fn switch_miaoshou(
    cred: &Value,
    account_id: &str,
    label: &str,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    let path = miaoshou_auth_file()
        .ok_or_else(|| anyhow!("没找到妙手的登录态文件（客户端还没登录过？）"))?;

    // 以客户端当前的文件为模板，保证 loginType / tokenType / entId 这些字段不丢
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    let mut parsed: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));

    let uid = cred
        .get("uid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| account_id.to_string());

    let token = cred["access_token"].as_str().unwrap_or("").to_string();

    // auth 段：保留原字段，只换 token
    let mut auth = parsed["auth"].as_object().cloned().unwrap_or_default();
    auth.insert("accessToken".into(), json!(token));
    if auth.get("loginType").is_none() {
        auth.insert("loginType".into(), json!("passport"));
    }
    if auth.get("tokenType").is_none() {
        auth.insert("tokenType".into(), json!("Bearer"));
    }

    // account 段：整体换成目标账号
    let mut account = parsed["account"].as_object().cloned().unwrap_or_default();
    account.insert("uid".into(), json!(uid));
    account.insert("name".into(), json!(label));
    account.insert("loginName".into(), json!(label));

    parsed["auth"] = Value::Object(auth);
    parsed["account"] = Value::Object(account);
    parsed["scopeSuffix"] = json!(format!("-{uid}"));
    parsed["updatedAt"] = json!(chrono::Utc::now().timestamp_millis());

    let backup = match super::client_backup::backup_client_login(
        "miaoshou",
        &[(path.clone(), backup_name_of(&path))],
        "switch",
    ) {
        Ok(b) => Some(b.dir),
        Err(err) => {
            eprintln!("备份客户端登录态失败（不影响本次切换）：{err}");
            None
        }
    };
    atomic_write(&path, serde_json::to_string_pretty(&parsed)?.as_bytes())?;

    on_progress("launching");
    let client_exe = crate::core::launcher::launch("miaoshou")
        .map_err(|e| anyhow!("凭据已写入客户端登录态，但客户端启动失败：{e}"))?;
    Ok(SwitchOutcome {
        backup,
        target_file: path.to_string_lossy().to_string(),
        client_exe: client_exe.to_string_lossy().to_string(),
        chat_sync: None,
    })
}

// ---------------------------------------------------------------------------
// Qoder CN（Electron safeStorage 加密：可检测，也可注入）
// ---------------------------------------------------------------------------

/// Qoder CN 客户端的 Electron userData 目录。
fn qoder_user_data() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    let dir = PathBuf::from(appdata).join("com.qodercn.app.stable");
    dir.is_dir().then_some(dir)
}

/// 解密客户端的 `auth.v1.dat`（OSCrypt v10）。文件不存在返回 `Ok(None)`。
fn qoder_read_auth() -> Result<Option<Value>> {
    let Some(dir) = qoder_user_data() else {
        return Ok(None);
    };
    let auth_file = dir.join("auth.v1.dat");
    if !auth_file.is_file() {
        return Ok(None);
    }
    let key = os_crypt::read_key(&dir.join("Local State"))?;
    let data = std::fs::read(&auth_file)?;
    let plain = os_crypt::decrypt(&key, &data)?;
    let json = serde_json::from_slice(&plain)
        .map_err(|e| anyhow!("auth.v1.dat 解密成功但内容不是 JSON：{e}"))?;
    Ok(Some(json))
}

/// 账号 id 与设备授权时保持一致：sha256(uid) 前 16 位十六进制。
/// 毫秒时间戳 → RFC3339（auth.v1.dat 里的 `expiresAt` 用这种格式，如 `2026-11-12T09:16:12Z`）。
fn ms_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// RFC3339 → 毫秒时间戳（读 auth.v1.dat 时用）。
fn rfc3339_to_ms(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0)
}

/// Qoder 客户端**当前登录**的账号 + 完整凭据（解密 `auth.v1.dat`，只读不写）。
///
/// 「切换客户端账号」切走前用它把当前登录捕获进账号池 —— 客户端同一时刻
/// 只能登一个号，切走后这份凭据就丢了；先捕获，谁都不丢。
/// 这里连 `authenticationContext` 一起存进凭据，比设备授权拿到的还全。
pub fn qoder_client_login() -> Option<(crate::core::provider::Account, Value)> {
    let auth = qoder_read_auth().ok()??;
    let uid = auth["user"]["id"].as_str().filter(|s| !s.is_empty())?;
    let name = auth["user"]["name"].as_str().unwrap_or("");
    let account = crate::core::provider::Account {
        id: qoder_account_id(uid),
        provider: "qoder".to_string(),
        label: if name.is_empty() {
            format!("Qoder {}", &uid[..uid.len().min(12)])
        } else {
            name.to_string()
        },
        created_at: chrono::Utc::now().timestamp(),
        last_used: None,
        origin: "Qoder 客户端登录态".to_string(),
    };
    let cred = json!({
        "access_token": auth["token"].as_str().unwrap_or(""),
        "refresh_token": auth["refreshToken"].as_str().unwrap_or(""),
        "user_id": uid,
        "expires_at": auth["expiresAt"].as_str().map(rfc3339_to_ms).unwrap_or(0),
        "refresh_expires_at": auth["refreshTokenExpiresAt"].as_str().map(rfc3339_to_ms).unwrap_or(0),
        "machine_id": crate::providers::qoder::local_machine_id(),
        "region": "cn",
        "authentication_context": auth.get("authenticationContext").cloned().unwrap_or(Value::Null),
    });
    Some((account, cred))
}

/// 客户端当前登录的账号。
///
/// 首选解密 `auth.v1.dat`（登录态本体，最准）；解不了再退回
/// 客户端写的 `.qoder-app-status.json`。但如果状态文件**明确**说
/// `logged_in == false`，以它为准 —— 登出后 auth.v1.dat 可能还留着
/// 上一次登录的内容，直接解密会把「已登出」误报成「还登着」。
fn detect_qoder() -> Option<DetectedAccount> {
    if let Some(logged_in) = qoder_status_logged_in() {
        if !logged_in {
            return None;
        }
    }
    if let Ok(Some(auth)) = qoder_read_auth() {
        let uid = auth["user"]["id"].as_str().unwrap_or("");
        if !uid.is_empty() {
            return Some(DetectedAccount {
                account_id: qoder_account_id(uid),
                label: auth["user"]["name"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    detect_qoder_from_status()
}

/// 读状态文件的 `logged_in` 字段；文件不在 / 解析不了返回 None（当作「不知道」）。
fn qoder_status_logged_in() -> Option<bool> {
    let home = dirs::home_dir()?;
    let path = home.join(".qoder-cn").join(".qoder-app-status.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    parsed["logged_in"].as_bool()
}

/// 兜底：客户端最近一次运行时写的状态文件里带着 uid。
fn detect_qoder_from_status() -> Option<DetectedAccount> {
    let home = dirs::home_dir()?;
    let path = home.join(".qoder-cn").join(".qoder-app-status.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    if parsed["logged_in"].as_bool() != Some(true) {
        return None;
    }
    let url = parsed["avatar_url"].as_str()?;
    // 形如 https://qoder.com.cn/users/<uid>/default/avatars
    let uid = url.split('/').find(|s| s.len() >= 32 && s.contains('-'))?;
    Some(DetectedAccount {
        account_id: qoder_account_id(uid),
        label: parsed["name"].as_str().unwrap_or("").to_string(),
    })
}

/// `authenticationContext` 的默认值（受众列表，账号无关，实测值）。
/// 仅当客户端还没有 `auth.v1.dat`（从未登录过）时才用它，否则从现有文件里抄。
const QODER_DEFAULT_AUTH_CONTEXT: &str = r#"["https://qoder.cn","https://openapi.qoder.com.cn","732aef47-9cf2-46a2-95fe-4cebb5d0d1fa","prod"]"#;

pub(crate) fn qoder_switch_dir() -> Result<PathBuf> {
    let dir = qoder_user_data()
        .ok_or_else(|| anyhow!("没有找到 Qoder CN 客户端的数据目录，请先启动客户端"))?;
    if !dir.join("Local State").is_file() {
        return Err(anyhow!("Qoder CN 客户端尚未初始化登录态，请先启动客户端"));
    }
    Ok(dir)
}

fn switch_qoder(
    cred: &Value,
    _account_id: &str,
    label: &str,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    let dir = qoder_switch_dir()?;
    let auth_file = dir.join("auth.v1.dat");

    // AES 密钥来自 Local State（DPAPI 保护）；客户端至少完整启动过一次才会有
    let key = os_crypt::read_key(&dir.join("Local State"))?;

    // authenticationContext（账号无关的受众列表）：优先用凭据里存的
    //（从客户端捕获的凭据带原值），其次抄现有文件，最后用实测默认值
    let current = qoder_read_auth()?;
    let context = cred
        .get("authentication_context")
        .filter(|v| !v.is_null())
        .cloned()
        .or_else(|| {
            current
                .as_ref()
                .and_then(|c| c.get("authenticationContext").cloned())
        })
        .unwrap_or_else(|| json!(QODER_DEFAULT_AUTH_CONTEXT));

    crate::providers::qoder::validate_switch_credential(cred)?;
    let uid = crate::providers::qoder::user_id_of(cred)
        .ok_or_else(|| anyhow!("账号凭据里没有 user_id，无法写入客户端登录态"))?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let expires_ms = cred.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
    // refresh token 的有效期设备授权时不一定下发；实测约一年。
    // 拿不到就写「一年后」，宁可写宽也不把客户端逼成「登录态已过期」。
    let refresh_expires_ms = cred
        .get("refresh_expires_at")
        .and_then(|v| v.as_i64())
        .filter(|v| *v > 0)
        .unwrap_or_else(|| now_ms + 365 * 24 * 3600 * 1000);

    let target = json!({
        "schemaVersion": 1,
        "token": cred["access_token"].as_str().unwrap_or(""),
        "refreshToken": cred["refresh_token"].as_str().unwrap_or(""),
        "expiresAt": ms_to_rfc3339(if expires_ms > 0 { expires_ms } else { now_ms }),
        "refreshTokenExpiresAt": ms_to_rfc3339(refresh_expires_ms),
        "user": {
            "id": uid,
            "name": label,
            "email": "",
            "phone": "",
            "avatarUrl": "",
        },
        "authenticationContext": context,
    });

    let plain = serde_json::to_vec_pretty(&target)?;
    let blob = os_crypt::encrypt(&key, &plain)?;

    let backup = if auth_file.is_file() {
        match super::client_backup::backup_client_login(
            "qoder",
            &[(auth_file.clone(), backup_name_of(&auth_file))],
            "switch",
        ) {
            Ok(b) => Some(b.dir),
            Err(err) => {
                eprintln!("备份客户端登录态失败（不影响本次切换）：{err}");
                None
            }
        }
    } else {
        None
    };
    atomic_write(&auth_file, &blob)?;

    on_progress("launching");
    let client_exe = crate::core::launcher::launch("qoder")
        .map_err(|e| anyhow!("凭据已写入客户端登录态，但客户端启动失败：{e}"))?;
    Ok(SwitchOutcome {
        backup,
        target_file: auth_file.to_string_lossy().to_string(),
        client_exe: client_exe.to_string_lossy().to_string(),
        chat_sync: None,
    })
}

// ---------------------------------------------------------------------------
// Trae CN（%APPDATA%\Trae CN\User\globalStorage\storage.json）
// ---------------------------------------------------------------------------

/// 把目标账号的凭据写进 Trae 的 storage.json，然后启动客户端。
///
/// 登录态和授权绑定的设备密钥一并写入，客户端继续共享本地会话和工作区。
fn switch_trae(
    cred: &Value,
    _account_id: &str,
    _label: &str,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    on_progress("writing");
    let written = crate::providers::trae::write_local_credential(cred, true, "switch")
        .map_err(|e| anyhow!("写入 Trae 登录态失败：{e}"))?;

    on_progress("launching");
    let client_exe = crate::core::launcher::launch("trae")
        .map_err(|e| anyhow!("凭据已写入 Trae 登录态，但客户端启动失败：{e}"))?;
    Ok(SwitchOutcome {
        backup: written.backup,
        target_file: written.storage_path.to_string_lossy().to_string(),
        client_exe: client_exe.to_string_lossy().to_string(),
        chat_sync: None,
    })
}

// ---------------------------------------------------------------------------
// WorkBuddy（腾讯 CodeBuddy：state.vscdb 的 safeStorage secret 键）
// ---------------------------------------------------------------------------

/// WorkBuddy 当前登录的账号。
///
/// 有共享 auth 文件 = 新客户端（5.6+）：只认它，读 uid（明文，不用起密钥
/// 辅助进程 —— overview 每 45s 轮询检测，不能每轮都拉客户端 exe），昵称加密
/// 时拿 uid 兜底。登出标记 / 解不开都如实返回 None —— **不回退**老 state.vscdb
/// （那是旧账号的陈旧数据，登出场景会误报「还登着」）。
/// 没有共享 auth 文件 = 老客户端，才解密 state.vscdb 的 secret 键。
fn detect_trae() -> Option<DetectedAccount> {
    let (account, _) = crate::providers::trae::read_local_account()?;
    Some(DetectedAccount {
        account_id: account.id,
        label: account.label,
    })
}

fn detect_workbuddy() -> Option<DetectedAccount> {
    if let Some(auth_path) = crate::core::wb_session::auth_file() {
        if auth_path.is_file() {
            return crate::core::wb_session::detect_identity().map(|(uid, label)| {
                DetectedAccount {
                    account_id: uid,
                    label,
                }
            });
        }
    }
    let secret = crate::providers::workbuddy::read_local_secret()?;
    let uid = secret["account"]["uid"]
        .as_str()
        .filter(|s| !s.is_empty())?;
    Some(DetectedAccount {
        account_id: uid.to_string(),
        label: secret["account"]["nickname"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    })
}

/// 捕获 WorkBuddy 客户端当前登录的账号（切换前调用，只读客户端文件）。
///
/// 新版：解密共享 auth 文件，凭据里多存一个 `account_profile`
/// （该账号自己的 account 块；切换时当模板，避免拿旧账号的身份字段张冠李戴）。
/// 老版：解密 state.vscdb。都拿不到返回 None。
pub fn workbuddy_client_login() -> Option<(crate::core::provider::Account, Value)> {
    // 新版共享 auth 文件；解不了就如实返回 None —— 有这个文件就是新客户端，
    // 不回退去读老的 state.vscdb（那是旧账号的陈旧数据）
    if let Some(auth_path) = crate::core::wb_session::auth_file() {
        if auth_path.is_file() {
            let raw = crate::core::wb_session::read_session_raw()?;
            let session = crate::core::wb_session::decode_session(&raw).ok()?;
            let uid = session["account"]["uid"]
                .as_str()
                .filter(|s| !s.is_empty())?
                .to_string();
            let access = session["auth"]["accessToken"].as_str().unwrap_or("");
            if access.is_empty() {
                return None;
            }
            let nickname = session["account"]["nickname"].as_str().unwrap_or("");
            let account = crate::core::provider::Account {
                id: uid.clone(),
                provider: "workbuddy".to_string(),
                label: if nickname.is_empty() {
                    format!("WorkBuddy {}", &uid[..uid.len().min(8)])
                } else {
                    nickname.to_string()
                },
                created_at: chrono::Utc::now().timestamp(),
                last_used: None,
                origin: "WorkBuddy 客户端登录态".to_string(),
            };
            let cred = json!({
                "access_token": access,
                "refresh_token": session["auth"]["refreshToken"].as_str().unwrap_or(""),
                "expires_at": session["auth"]["expiresAt"].as_i64().unwrap_or(0),
                "uid": uid,
                "domain": session["auth"]["domain"].as_str().unwrap_or(""),
                "account_profile": session["account"].clone(),
            });
            return Some((account, cred));
        }
    }

    // 老客户端：state.vscdb 的 secret 键
    let secret = crate::providers::workbuddy::read_local_secret()?;
    let uid = secret["account"]["uid"]
        .as_str()
        .filter(|s| !s.is_empty())?;
    let nickname = secret["account"]["nickname"].as_str().unwrap_or("");
    let account = crate::core::provider::Account {
        id: uid.to_string(),
        provider: "workbuddy".to_string(),
        label: if nickname.is_empty() {
            format!("WorkBuddy {}", &uid[..uid.len().min(8)])
        } else {
            nickname.to_string()
        },
        created_at: chrono::Utc::now().timestamp(),
        last_used: None,
        origin: "WorkBuddy 客户端登录态".to_string(),
    };
    let cred = json!({
        "access_token": secret["token"].as_str().unwrap_or(""),
        "refresh_token": secret["refreshToken"].as_str().unwrap_or(""),
        "expires_at": secret["expiresAt"].as_i64().unwrap_or(0),
        "uid": uid,
        "domain": secret["domain"].as_str().unwrap_or(""),
        "account_profile": secret["account"].clone(),
    });
    Some((account, cred))
}

/// 备份 sqlite 三件套（主文件 + -wal + -shm）成 `<file>.bak` 系列同名文件。
///
/// 与其它平台的「最多留一份我们自己的备份」策略一致：
/// 客户端启动后自己也会写 `state.vscdb.backup`，互不干扰。
fn backup_sqlite(path: &std::path::Path) -> Result<Option<String>> {
    let mut first = None;
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let src = PathBuf::from(&name);
        if !src.is_file() {
            continue;
        }
        let mut bak_name = path.as_os_str().to_os_string();
        bak_name.push(format!("{suffix}.bak"));
        let bak = PathBuf::from(&bak_name);
        if !bak.exists() {
            std::fs::copy(&src, &bak)?;
        }
        if first.is_none() {
            first = Some(bak.to_string_lossy().to_string());
        }
    }
    Ok(first)
}

fn switch_workbuddy(
    cred: &Value,
    _account_id: &str,
    label: &str,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    // 新版客户端（5.6+）登录态在共享 auth 文件里 —— 有这个文件就以它为准
    // （对齐 Cockpit 的 workbuddy 切号：官方加密字段读写）；没有则是老客户端，
    // 走下面的 state.vscdb 老路。
    if let Some(auth_path) = crate::core::wb_session::auth_file() {
        if auth_path.is_file() {
            let (target_file, backup) = crate::core::wb_session::write_switch(cred, label)?;
            on_progress("launching");
            let client_exe = crate::core::launcher::launch("workbuddy")
                .map_err(|e| anyhow!("凭据已写入客户端登录态，但客户端启动失败：{e}"))?;
            return Ok(SwitchOutcome {
                backup: backup.map(|p| p.to_string_lossy().to_string()),
                target_file: target_file.to_string_lossy().to_string(),
                client_exe: client_exe.to_string_lossy().to_string(),
                chat_sync: None,
            });
        }
    }

    // ---- 老客户端：state.vscdb 的 secret 键（safeStorage 重加密写回）----
    let dir = crate::providers::workbuddy::user_data_dir()
        .ok_or_else(|| anyhow!("没有找到 WorkBuddy 客户端的数据目录（客户端从未运行过？）"))?;
    let db_path = dir.join("User").join("globalStorage").join("state.vscdb");
    if !db_path.is_file() {
        return Err(anyhow!("没找到 WorkBuddy 的登录态库 state.vscdb"));
    }
    let key = os_crypt::read_key(&dir.join("Local State"))?;

    // 以客户端当前的 secret 原文作登录态模板。客户端从没登录过就没有模板，如实报错。
    let current = crate::providers::workbuddy::read_local_secret().ok_or_else(|| {
        anyhow!("读取 WorkBuddy 当前登录态失败：请先在客户端登录任意账号一次，再使用切换")
    })?;

    let uid = cred
        .get("uid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("账号凭据里没有 uid，无法写入 WorkBuddy 登录态"))?;

    let mut secret = current;
    let mut account = cred
        .get("account_profile")
        .filter(|profile| !crate::core::wb_session::contains_encrypted_wrapper(profile))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    account.insert("uid".into(), json!(uid));
    account.insert("nickname".into(), json!(label));
    secret["account"] = Value::Object(account);
    secret["token"] = json!(cred["access_token"].as_str().unwrap_or(""));
    secret["refreshToken"] = json!(cred["refresh_token"].as_str().unwrap_or(""));
    if let Some(ms) = cred.get("expires_at").and_then(|v| v.as_i64()) {
        secret["expiresAt"] = json!(ms);
    }
    if let Some(domain) = cred
        .get("domain")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        secret["domain"] = json!(domain);
    }

    // safeStorage 重加密，写回 {type:"Buffer",data:[…]} 形态（与客户端自写格式一致）
    let plain = serde_json::to_vec(&secret)?;
    let blob = os_crypt::encrypt(&key, &plain)?;
    let wrapper = json!({ "type": "Buffer", "data": blob });

    let backup = backup_sqlite(&db_path)?;
    let payload = serde_json::to_string(&wrapper)?;
    let mut changed = 0u64;
    {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow!("打开 state.vscdb 失败：{e}"))?;
        for k in crate::providers::workbuddy::secret_keys() {
            conn.execute(
                "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?1, ?2)",
                rusqlite::params![k, payload],
            )
            .map_err(|e| anyhow!("写回登录态失败：{e}"))?;
            changed += conn.changes();
        }
    }
    if changed == 0 {
        return Err(anyhow!(
            "state.vscdb 里没有 WorkBuddy 的登录态键（客户端版本可能已变更键名），未做任何修改"
        ));
    }

    on_progress("launching");
    let client_exe = crate::core::launcher::launch("workbuddy")
        .map_err(|e| anyhow!("凭据已写入客户端登录态，但客户端启动失败：{e}"))?;
    Ok(SwitchOutcome {
        backup,
        target_file: db_path.to_string_lossy().to_string(),
        client_exe: client_exe.to_string_lossy().to_string(),
        chat_sync: None,
    })
}

// ---------------------------------------------------------------------------
// 豆包工作（DoubaoWork）换号
// ---------------------------------------------------------------------------

pub fn detect_doubaowork() -> Option<DetectedAccount> {
    let user_data = crate::providers::doubaowork::find_doubao_user_data()?;
    let local_state_path = user_data.join("Local State");
    let state_bytes = std::fs::read(&local_state_path).ok()?;
    let state_json: Value = serde_json::from_slice(&state_bytes).ok()?;
    let last_used = state_json["profile"]["last_used"].as_str().unwrap_or("Default");
    let info = &state_json["profile"]["info_cache"][last_used];
    let name = info["name"].as_str().unwrap_or(last_used);

    Some(DetectedAccount {
        account_id: last_used.to_string(),
        label: name.to_string(),
    })
}

fn switch_doubaowork(
    cred: &Value,
    _account_id: &str,
    _label: &str,
    on_progress: &mut impl FnMut(&str),
) -> Result<SwitchOutcome> {
    let user_data = crate::providers::doubaowork::find_doubao_user_data()
        .ok_or_else(|| anyhow!("未找到豆包工作数据目录"))?;
    let local_state_path = user_data.join("Local State");
    let state_bytes = std::fs::read(&local_state_path)?;
    let mut state_json: Value = serde_json::from_slice(&state_bytes)?;

    let target_profile = cred["profileDir"].as_str().unwrap_or("Default");

    // 备份 Local State
    let backup_path = local_state_path.with_extension("bak");
    let _ = std::fs::copy(&local_state_path, &backup_path);

    // 修改 profile.last_used
    if let Some(profile_obj) = state_json.get_mut("profile").and_then(|p| p.as_object_mut()) {
        profile_obj.insert("last_used".to_string(), json!(target_profile));
    }

    let updated_bytes = serde_json::to_vec_pretty(&state_json)?;
    atomic_write(&local_state_path, &updated_bytes)?;

    on_progress("restarting");
    let profile_arg = format!("--profile-directory={}", target_profile);
    let exe = crate::core::launcher::launch_with_args("doubaowork", &[&profile_arg])?;

    Ok(SwitchOutcome {
        backup: Some(backup_path.to_string_lossy().to_string()),
        target_file: local_state_path.to_string_lossy().to_string(),
        client_exe: exe.to_string_lossy().to_string(),
        chat_sync: None,
    })
}

// ---------------------------------------------------------------------------
// 备份
// ---------------------------------------------------------------------------

/// 备份里的文件名：用原始文件名（各平台登录态文件名不同）。
fn backup_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("login-state.bin")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 记录键必须和客户端自己算出来的一模一样 —— 算错了客户端就认不出这条凭据。
    ///
    /// 向量取自本机 MiniMax Code 3.1.10 实际写下的 auth.json（2026-11-02 实测）：
    /// 客户端 app.asar 的 `namespace.js` 用
    /// `base64url(sha256("{authHome}\0mcode-public"))` 算 account，
    /// 再拼上 `com.minimax.mcode.oauth.{buildEnv}.{region}`。
    #[test]
    fn MiniMax记录键_按客户端公式推导() {
        let auth_home = PathBuf::from(r"C:\Users\admin\.minimax\auth");
        let key = minimax_record_key(&auth_home, "prod", "cn");
        assert_eq!(
            key,
            "com.minimax.mcode.oauth.prod.cn\u{0}grC2d5YJs_EtHBAZCQ35ndtpxNeJnNSTYgg-sW-zBSQ"
        );
    }

    /// 从登录态文件路径反推命名空间：`<authHome>/<buildEnv>/<region>/mcode-public/auth.json`
    #[test]
    fn MiniMax命名空间_从登录态路径反推() {
        let path = PathBuf::from(r"C:\Users\admin\.minimax\auth\prod\cn\mcode-public\auth.json");
        let (auth_home, build_env, region) = minimax_namespace(&path).unwrap();
        assert_eq!(auth_home, PathBuf::from(r"C:\Users\admin\.minimax\auth"));
        assert_eq!(build_env, "prod");
        assert_eq!(region, "cn");
    }

    /// 回归测试（2026-11-04）：曾经把路径写成 `%APPDATA%\CodeBuddy`、键名写成
    /// `accessToken`（旧版客户端的），结果「切换成功但客户端账号没变」。
    /// WorkBuddy 客户端实际读的是 `%APPDATA%\WorkBuddy` + `accessTokencn`。
    #[test]
    fn workbuddy_登录态路径与键名是WorkBuddy的() {
        let keys = crate::providers::workbuddy::secret_keys();
        assert_eq!(keys.len(), 1, "只写 WorkBuddy 用的键，不写旧 CodeBuddy 的");
        assert!(
            keys[0].contains("planning-genie.new.accessTokencn"),
            "键名应是 accessTokencn：{}",
            keys[0]
        );
        if let Some(dir) = crate::providers::workbuddy::user_data_dir() {
            let name = dir.file_name().unwrap_or_default().to_string_lossy();
            assert_eq!(name, "WorkBuddy", "数据目录应是 WorkBuddy，实际 {dir:?}");
        }
    }

    /// 诊断用：验证「捕获客户端登录态」拿到的是活凭据（切换链路修复的前提）。
    ///
    /// 只读：读客户端 auth.json + token 实测，不写文件、不碰客户端进程。
    /// 手动验证：`cargo test -- --ignored 客户端登录态捕获能拿到活凭据 --nocapture`
    #[tokio::test]
    #[ignore = "依赖本机 MiniMax 客户端与登录态，手动跑"]
    async fn 客户端登录态捕获能拿到活凭据() {
        let (id, name, cred) = crate::providers::minimax::client_session()
            .await
            .expect("读不到客户端登录态");
        let expires = cred["expires_at_ms"].as_i64().unwrap_or(0);
        let now = chrono::Utc::now().timestamp_millis();
        eprintln!("client_session: {name} <{id}> 剩余 {} ms", expires - now);
        assert!(
            expires > now,
            "捕获到的凭据应还有效（剩 {} ms）—— 若已过期，说明捕获时机在客户端刷新前，\
             切换会写死凭据（2026-11-05 丢账号态的根因）",
            expires - now
        );
        assert!(cred["access_token"].as_str().is_some_and(|s| !s.is_empty()));
    }

    /// 诊断用：打印池里 minimax 账号的凭据关键字段（token 打码，只看有效期/
    /// 代数/登录纪元）。用于排查「切换后客户端丢账号态」。
    /// 手动验证：`cargo test -- --ignored 池里minimax凭据体检 --nocapture`
    #[test]
    #[ignore = "依赖本机账号池，手动跑"]
    fn 池里minimax凭据体检() {
        let store = crate::core::store::AccountStore::load().expect("加载账号池失败");
        for acc in store.list_of("minimax") {
            let Ok(cred) = store.credential("minimax", &acc.id) else {
                eprintln!("{} <{}> 凭据解密失败", acc.label, acc.id);
                continue;
            };
            let mask = |k: &str| {
                cred[k]
                    .as_str()
                    .map(|s| format!("{}…({})", &s[..s.len().min(8)], s.len()))
                    .unwrap_or_default()
            };
            eprintln!(
                "{} <{}> origin={}\n  access={} refresh={}\n  expires_at_ms={} login_epoch={} auth_file={}",
                acc.label,
                acc.id,
                acc.origin,
                mask("access_token"),
                mask("refresh_token"),
                cred["expires_at_ms"],
                cred["login_epoch"],
                cred["auth_file"],
            );
        }
    }

    /// 诊断用：真实客户端登录态捕获（**只读**，不写任何文件）。
    ///
    /// 验证新版链路：共享 auth 文件 → 官方密钥解密 → 凭据带 account_profile；
    /// detect 与 capture 的身份一致。
    /// 手动验证：`cargo test -- --ignored 真实WorkBuddy客户端登录态能捕获 --nocapture`
    #[test]
    #[ignore = "依赖本机 WorkBuddy 客户端与登录态，手动跑"]
    fn 真实WorkBuddy客户端登录态能捕获() {
        let (account, cred) =
            workbuddy_client_login().expect("捕获失败：读不到/解不开客户端登录态");
        eprintln!(
            "account = {} <{}> · domain = {}",
            account.label, account.id, cred["domain"]
        );
        assert!(!account.id.is_empty());
        assert!(
            cred["access_token"].as_str().is_some_and(|s| !s.is_empty()),
            "access_token 应解出非空明文"
        );
        assert!(cred["account_profile"].is_object());
        // detect（overview 轮询用的那条路径）与 capture 身份一致
        let detected = detect_workbuddy().expect("detect 失败");
        assert_eq!(detected.account_id, account.id);
    }
}
