//! 定位 / 启动各 agent 的客户端，以及「客户端是否在运行」的检测。
//!
//! 「多账号切换」在这里落地为两件事：
//!   1. 账号池里标记哪个账号是该 agent 的**当前账号**（`config.activeAccounts`）；
//!   2. 一键**打开客户端**，直接进到该账号的会话里继续干活。
//!
//! 说明：本机各客户端（MiniMax Code / Qoder CN）默认是**单账号**的，切换账号
//! 需要客户端自己重新登录。这里做的是「把客户端拉起来并带上账号上下文」，
//! 而不是像 Cockpit 的 workbuddy 那样给每个账号一份独立数据目录 ——
//! 那需要每个账号一个隔离的 userData，属于更大的架构改动。
//!
//! exe 定位策略（按优先级）：
//!   1. **App Paths 注册表**（安装器注册的，最准；用 `winreg` crate 读，无编码问题）；
//!   2. **标准安装根两级目录扫描**：Program Files / Program Files (x86) /
//!      ProgramData / LocalAppData / 各盘符 `:\Programs`，按目录名关键词匹配；
//!      Qoder 的版本化布局（`<安装根>\.qoder-versions\<版本>\`）单独处理；
//!   3. 旧版本写死的路径，作为最后兜底（换机器后 1、2 基本能兜住）。

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// 各平台客户端的静态描述。
struct ClientSpec {
    /// 候选 exe 文件名（第一个是主程序，其余是启动器这类次要候选）
    exe_names: &'static [&'static str],
    /// 安装目录名关键词（小写包含匹配）
    dir_keywords: &'static [&'static str],
    /// 旧版本写死的路径（最后的兜底）
    legacy_paths: &'static [&'static str],
}

fn spec_of(provider: &str) -> Option<ClientSpec> {
    match provider {
        "minimax" => Some(ClientSpec {
            exe_names: &["MiniMax Code.exe"],
            dir_keywords: &["minimax"],
            legacy_paths: &[
                r"D:\Programs\MiniMax Code\MiniMax Code.exe",
                r"C:\Program Files\MiniMax Code\MiniMax Code.exe",
            ],
        }),
        "qoder" => Some(ClientSpec {
            // Launcher 是次要候选：真正的客户端在 .qoder-versions\<版本>\ 下
            exe_names: &["Qoder CN.exe", "Qoder CN Launcher.exe"],
            dir_keywords: &["qoder"],
            legacy_paths: &[r"C:\Program Files\Qoder CN\Qoder CN.exe"],
        }),
        "miaoshou" => Some(ClientSpec {
            exe_names: &["妙手.exe"],
            dir_keywords: &["妙手", "catpaw", "meituan"],
            legacy_paths: &[
                r"D:\meituan\妙手\妙手.exe",
                r"C:\Program Files\妙手\妙手.exe",
            ],
        }),
        "trae" => Some(ClientSpec {
            exe_names: &["Trae CN.exe"],
            dir_keywords: &["trae cn", "trae"],
            legacy_paths: &[r"D:\Programs\Trae CN\Trae CN.exe"],
        }),
        "workbuddy" => Some(ClientSpec {
            // 腾讯 WorkBuddy（原 CodeBuddy CN 桌面端）。只认 WorkBuddy：
            // 本工具的登录态写在 `%APPDATA%\WorkBuddy`，旧 CodeBuddy 用的是
            // `%APPDATA%\CodeBuddy`，打开它不会读到切换后的账号。
            exe_names: &["WorkBuddy.exe"],
            dir_keywords: &["workbuddy"],
            legacy_paths: &[],
        }),
        "zcode" => Some(ClientSpec {
            // 智谱 Zcode（Z.ai），安装目录名 `ZCode`
            exe_names: &["ZCode.exe"],
            dir_keywords: &["zcode"],
            legacy_paths: &[r"D:\Program Files\ZCode\ZCode.exe"],
        }),
        "doubaowork" => Some(ClientSpec {
            exe_names: &["Doubao.exe", "DoubaoWork.exe"],
            dir_keywords: &["doubao", "doubaowork"],
            legacy_paths: &[r"C:\Users\mszl5\AppData\Local\Doubao\Application\Doubao.exe"],
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// exe 定位
// ---------------------------------------------------------------------------

/// App Paths 注册表：安装器会在这里注册 exe 的完整路径。
///
/// 用 `winreg` 直接调 W 版 API，中文路径不会有 `reg query` 的控制台编码问题。
fn app_paths_lookup(exe_name: &str) -> Option<PathBuf> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let key = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}");
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let Ok(sub) = RegKey::predef(hive).open_subkey(&key) else {
            continue;
        };
        if let Ok(path) = sub.get_value::<String, _>("") {
            let p = PathBuf::from(path.trim_matches('"'));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// 要扫描的标准安装根。
fn scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
        if let Some(v) = std::env::var_os(var) {
            roots.push(PathBuf::from(v));
        }
    }
    if let Some(local) = dirs::data_local_dir() {
        roots.push(local.clone());
        roots.push(local.join("Programs"));
    }
    if let Some(appdata) = dirs::data_dir() {
        roots.push(appdata);
    }
    // 各盘符根下的 \Programs（覆盖 D:\Programs 这类自装位置）
    for letter in b'C'..=b'Z' {
        let programs = PathBuf::from(format!("{}:\\Programs", letter as char));
        if programs.is_dir() {
            roots.push(programs);
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

/// 找出本机所有「名字像这个客户端」的安装目录。
///
/// 两级扫描：根下的目录名匹配关键词就纳入，并继续看它子目录里匹配的
/// （覆盖 `LocalAppData\Qoder CN\Qoder CN Launcher\` 这种嵌套布局）。
/// App Paths 注册表定位到的 exe，其父目录链也一并纳入。
fn matching_dirs(spec: &ClientSpec) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    for exe in spec.exe_names {
        if let Some(p) = app_paths_lookup(exe) {
            let mut cur = p.parent().map(Path::to_path_buf);
            while let Some(dir) = cur {
                out.push(dir.clone());
                cur = dir.parent().map(Path::to_path_buf);
            }
        }
    }

    for root in scan_roots() {
        let mut level = vec![root];
        for _ in 0..2 {
            let mut next = Vec::new();
            for dir in &level {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if !spec.dir_keywords.iter().any(|k| name.contains(k)) {
                        continue;
                    }
                    let path = entry.path();
                    if path.is_dir() {
                        out.push(path.clone());
                        next.push(path);
                    }
                }
            }
            level = next;
            if level.is_empty() {
                break;
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Qoder 的版本化布局：真实客户端在 `<安装根>\.qoder-versions\<版本>\` 下，
/// 取语义化版本最大的那个。
fn qoder_versioned_exe(root: &Path) -> Option<PathBuf> {
    let versions = root.join(".qoder-versions");
    let Ok(entries) = std::fs::read_dir(&versions) else {
        return None;
    };
    let mut found: Vec<(u64, u64, u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let mut parts = name.split('.');
        let a = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let b = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let c = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        found.push((a, b, c, entry.path()));
    }
    found
        .into_iter()
        .max()
        .map(|(_, _, _, dir)| dir.join("Qoder CN.exe"))
        .filter(|p| p.is_file())
}

/// 找某 agent 的客户端可执行文件。
pub fn client_exe(provider: &str) -> Option<PathBuf> {
    let Some(spec) = spec_of(provider) else {
        return None;
    };
    let dirs = matching_dirs(&spec);

    // 先只找主 exe（含 Qoder 版本化布局），避免被「启动器」抢先
    if let Some(primary) = spec.exe_names.first() {
        for dir in &dirs {
            let p = dir.join(primary);
            if p.is_file() {
                return Some(p);
            }
            if let Some(hit) = qoder_versioned_exe(dir) {
                return Some(hit);
            }
        }
    }
    // 再找次要候选（Qoder CN Launcher 这类）
    for dir in &dirs {
        for exe in spec.exe_names.iter().skip(1) {
            let p = dir.join(exe);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // 最后：旧版本写死的路径
    spec.legacy_paths
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// 本机能找到的全部 Qoder 版本号（`Cosy-Version` 请求头用）。
pub fn qoder_versions() -> Vec<String> {
    let Some(spec) = spec_of("qoder") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for dir in matching_dirs(&spec) {
        let Ok(entries) = std::fs::read_dir(dir.join(".qoder-versions")) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 客户端本地数据目录（账号的项目/会话都在这里）。
pub fn data_dir(provider: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let dir = match provider {
        "minimax" => home.join(".minimax"),
        "qoder" => home.join(".qoder-cn"),
        "miaoshou" => home.join(".meituan-catpaw"),
        "workbuddy" => home.join(".workbuddy"),
        "zcode" => home.join(".zcode"),
        // Trae CN 的 Electron userData 在 %APPDATA%\Trae CN，不在用户主目录下。
        "trae" => PathBuf::from(std::env::var_os("APPDATA")?).join("Trae CN"),
        _ => return None,
    };
    if dir.is_dir() {
        Some(dir)
    } else {
        None
    }
}

/// 启动客户端。返回实际启动的可执行文件路径。
///
/// ⚠️ 必须**经 explorer 分离启动**：客户端不能作为本进程的直接子进程 ——
/// Electron 客户端启动时先拿单实例锁，拿不到就 `app.quit()` 秒退（退出码 0），
/// 表现是「提示切换成功，但客户端根本没起来」（2026-11-03 实测：从 GUI 宿主
/// 直接 spawn 必现；经 explorer / 控制台启动则正常）。
/// explorer 拉起等价于用户双击：进程上下文干净，父进程也不是我们。
///
/// 启动后还要**确认它真的活了** —— 客户端起不来时不能报成功，否则用户只看到
/// 「已切换并重启」却找不到客户端。
pub fn launch(provider: &str) -> Result<PathBuf> {
    launch_with_args(provider, &[])
}

pub fn launch_with_args(provider: &str, extra_args: &[&str]) -> Result<PathBuf> {
    let exe =
        client_exe(provider).ok_or_else(|| anyhow!("没有找到 {} 的客户端可执行文件", provider))?;

    if extra_args.is_empty() {
        let _ = spawn_hidden("explorer.exe", &[&exe.to_string_lossy()]);
    } else {
        let mut cmd_args = vec![exe.to_str().unwrap_or_default()];
        cmd_args.extend_from_slice(extra_args);
        let _ = spawn_hidden(&exe.to_string_lossy(), extra_args);
    }

    if wait_until_running(provider, std::time::Duration::from_secs(8)) {
        return Ok(exe);
    }

    // 没起来：退回直接 spawn，好把退出码如实带出来（explorer 路径拿不到退出码）
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(extra_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let mut child = cmd.spawn().map_err(|e| anyhow!("启动失败：{e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if is_running(provider) {
            return Ok(exe);
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(anyhow!(
                "客户端启动后立刻退出（退出码 {:?}）：请手动打开客户端",
                status.code()
            ));
        }
    }
    Err(anyhow!("客户端启动超时（没起来）：请手动打开客户端"))
}

/// 等客户端进程出现（Electron 主进程一起来就有进程名，不必等窗口）。
fn wait_until_running(provider: &str, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if is_running(provider) {
            return true;
        }
    }
    false
}

/// 以「不弹控制台窗口」的方式跑一个命令。
#[cfg(windows)]
fn spawn_hidden(program: &str, args: &[&str]) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
}

#[cfg(not(windows))]
fn spawn_hidden(program: &str, args: &[&str]) -> std::io::Result<std::process::Child> {
    std::process::Command::new(program).args(args).spawn()
}

// ---------------------------------------------------------------------------
// 进程检测（换号前必须确认客户端已完全退出）
// ---------------------------------------------------------------------------

/// 客户端进程的三种状态。
///
/// 关键区别：「**不知道**」≠「**没在跑**」。
/// 凭据刷新这类会**轮换 refresh token** 的动作，一旦不确定客户端状态，
/// 就必须按「可能还在跑」处理 —— 2026-11-11 上游 cockpit-tools 就是在这里
/// 把客户端手里的 RT 轮换掉、导致客户端掉线的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProcessState {
    /// 确认客户端进程存在
    Running,
    /// 确认没有客户端进程
    Absent,
    /// 枚举失败 / 平台不支持 —— 既不能确认在跑，也不能确认没跑
    Unknown,
}

/// 客户端进程状态（三态）。
///
/// 枚举失败返回 `Unknown` 而不是 `Absent`：调用方要区分
/// 「确认没在跑」（可以安全刷新凭据）与「不知道」（必须保守）。
pub fn client_process_state(provider: &str) -> ClientProcessState {
    process_state_from_names(provider, winproc::process_names_result())
}

/// 由「进程名枚举结果」推导三态（抽出来便于单测）。
pub fn process_state_from_names(
    provider: &str,
    names: Result<Vec<String>, String>,
) -> ClientProcessState {
    let Some(spec) = spec_of(provider) else {
        return ClientProcessState::Unknown;
    };
    let targets: Vec<String> = spec.exe_names.iter().map(|n| n.to_lowercase()).collect();
    match names {
        Ok(names) => {
            if names.iter().any(|name| targets.iter().any(|t| name == t)) {
                ClientProcessState::Running
            } else {
                ClientProcessState::Absent
            }
        }
        // 枚举失败 → 不知道，不是「没在跑」
        Err(_) => ClientProcessState::Unknown,
    }
}

/// 客户端是否正在运行。
///
/// 用 Toolhelp32 快照枚举进程名（W 版 API，中文 exe 名也正确），
/// 与该平台的候选 exe 名做不区分大小写的**全等**比较。
/// Electron 客户端的全部子进程都与其主 exe 同名，比到一个就算在运行。
///
/// ⚠️ 这是**布尔兼容层**：`Unknown`（枚举失败）一律当作 `false`。
/// 涉及刷新 / 改写客户端凭据的地方必须用 `client_process_state`，
/// 否则会在「不知道客户端是否在跑」时误轮换客户端的 refresh token。
pub fn is_running(provider: &str) -> bool {
    client_process_state(provider) == ClientProcessState::Running
}

/// 关闭客户端：先请求**优雅关闭**（等价于点窗口的 X），超时再强制结束树。
///
/// 「切换客户端账号」的一条龙（借鉴 Cockpit 的关闭→写入→重启）用它先收掉
/// 正在运行的客户端 —— 客户端退出时会把内存里的登录态写回文件，所以写凭据
/// 之前必须等进程**完全退出**。返回 false 表示实在关不掉（权限不足等）。
pub fn close_client(provider: &str) -> bool {
    let Some(spec) = spec_of(provider) else {
        return false;
    };
    if !is_running(provider) {
        return true;
    }

    // 1) 优雅关闭：taskkill 不带 /F 时给所有窗口发 WM_CLOSE。
    //    注意 Electron 应用可能「关到托盘」，所以等一小段再看。
    for exe in spec.exe_names {
        run_hidden("taskkill", &["/IM", exe, "/T"]);
    }
    if wait_until_stopped(provider, std::time::Duration::from_secs(4))
        && confirm_stable_exit(provider)
    {
        return true;
    }

    // 2) 强制结束进程树（客户端的鉴权日记本身就是按崩溃恢复设计的，能兜住）。
    //    Electron 的渲染/工具子进程可能比主进程晚退，收不干净就多收几轮。
    for _ in 0..3 {
        for exe in spec.exe_names {
            run_hidden("taskkill", &["/IM", exe, "/F", "/T"]);
        }
        if wait_until_stopped(provider, std::time::Duration::from_secs(4))
            && confirm_stable_exit(provider)
        {
            return true;
        }
    }
    false
}

/// 进程消失后确认「不再复活、没有晚退的子进程」。
///
/// 2026-10-25 实测踩坑：优雅关闭时客户端退出前会把内存会话写回登录态文件，
/// 子进程/收尾写盘可能比主进程晚一两拍 —— 只看「进程没了」就写凭据，
/// 会被它的收尾写入覆盖，切换白做。静默 1.5 秒复查两轮都干净才算真退出。
fn confirm_stable_exit(provider: &str) -> bool {
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(750));
        if is_running(provider) {
            return false;
        }
    }
    true
}

/// 轮询等待客户端完全退出。
fn wait_until_stopped(provider: &str, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !is_running(provider) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    !is_running(provider)
}

/// 静默跑一个命令（不弹控制台窗口）。
#[cfg(windows)]
fn run_hidden(program: &str, args: &[&str]) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

#[cfg(not(windows))]
fn run_hidden(program: &str, args: &[&str]) {
    let _ = std::process::Command::new(program).args(args).status();
}

#[cfg(windows)]
mod winproc {
    //! Toolhelp32 进程快照的 FFI。沿用 `dpapi.rs` 的做法：直接声明
    //! `extern "system"`，不引入 windows-sys 这类绑定 crate。

    use std::ffi::c_void;

    const TH32CS_SNAPPROCESS: u32 = 0x2;
    const INVALID_HANDLE_VALUE: *mut c_void = usize::MAX as *mut c_void;

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    impl ProcessEntry32W {
        fn zeroed() -> Self {
            Self {
                dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
                cnt_usage: 0,
                th32_process_id: 0,
                th32_default_heap_id: 0,
                th32_module_id: 0,
                cnt_threads: 0,
                th32_parent_process_id: 0,
                pc_pri_class_base: 0,
                dw_flags: 0,
                sz_exe_file: [0; 260],
            }
        }
    }

    extern "system" {
        fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
        fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
    }

    /// 全部进程名（小写）。
    ///
    /// 枚举失败返回 `Err` —— 调用方需要区分「枚举失败」与「确实没有该进程」：
    /// 前者是**不知道**，后者才是「没在跑」（两者对凭据刷新的含义相反）。
    pub fn process_names_result() -> Result<Vec<String>, String> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE || snap.is_null() {
                return Err("创建进程快照失败".to_string());
            }
            let mut out = Vec::new();
            let mut entry = ProcessEntry32W::zeroed();
            if Process32FirstW(snap, &mut entry) == 0 {
                CloseHandle(snap);
                return Err("枚举进程失败".to_string());
            }
            loop {
                let len = entry
                    .sz_exe_file
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..len]).to_lowercase();
                out.push(name);
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
            CloseHandle(snap);
            Ok(out)
        }
    }
}

#[cfg(not(windows))]
mod winproc {
    /// 非 Windows 上没有进程枚举 —— 一律「不知道」，
    /// 不能当成「客户端没在跑」（那会让凭据刷新顶掉客户端的登录）。
    pub fn process_names_result() -> Result<Vec<String>, String> {
        Err("当前平台不支持进程枚举".to_string())
    }
}

// ---------------------------------------------------------------------------
// 统计（只读，给 UI 一个「这个账号有多少东西」的直观感受）
// ---------------------------------------------------------------------------

/// 统计数据目录里的项目/会话数量。
pub fn account_stats(provider: &str) -> Option<(usize, usize)> {
    let home = dirs::home_dir()?;
    match provider {
        // MiniMax 的数据分两处：.minimax（会话/鉴权）与 .minimax-agent-cn（项目/配置）
        "minimax" => {
            let projects = home.join(".minimax-agent-cn").join("projects");
            let sessions = home.join(".minimax").join("v2").join("sessions");
            Some((count_dirs(&projects), count_dirs(&sessions)))
        }
        "qoder" => {
            let projects = home.join(".qoder-cn").join("projects");
            let sessions = home.join(".qoder-cn").join("logs").join("sessions");
            Some((count_dirs(&projects), count_dirs(&sessions)))
        }
        // 妙手的工作区在用户 id 目录下，结构因版本而异，只数一层
        "miaoshou" => {
            let root = home.join(".meituan-catpaw");
            Some((count_dirs(&root), count_files(&root, "auth.json")))
        }
        _ => None,
    }
}

fn count_files(dir: &Path, name: &str) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().file_name().and_then(|n| n.to_str()) == Some(name))
                .count()
        })
        .unwrap_or(0)
}

fn count_dirs(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 客户端exe能定位或至少不panic() {
        // 本机装了 MiniMax / Qoder / 妙手，定位应该成功；没装的机器只要求不 panic
        for provider in ["minimax", "qoder", "miaoshou", "unknown"] {
            let _ = client_exe(provider);
            let _ = is_running(provider);
        }
    }

    #[test]
    fn 进程名可枚举() {
        // 至少能列出当前进程（测试进程自身）
        let names = winproc::process_names_result().expect("Toolhelp32 应该能枚举到进程");
        assert!(!names.is_empty(), "Toolhelp32 应该能枚举到进程");
    }

    #[test]
    fn 进程状态三态_枚举失败算未知而不是没在跑() {
        // 枚举失败 → Unknown（不是 Absent）：调用方要区分「不知道」与「没在跑」，
        // 否则会在客户端其实还在跑的时候把它的 refresh token 轮换掉（掉线）。
        assert_eq!(
            process_state_from_names("minimax", Err("boom".to_string())),
            ClientProcessState::Unknown
        );
        // 枚举成功但没有客户端 → Absent
        assert_eq!(
            process_state_from_names("minimax", Ok(vec!["explorer.exe".to_string()])),
            ClientProcessState::Absent
        );
        // 枚举成功且命中 → Running
        assert_eq!(
            process_state_from_names("minimax", Ok(vec!["minimax code.exe".to_string()])),
            ClientProcessState::Running
        );
        // 未知平台 → Unknown
        assert_eq!(
            process_state_from_names("unknown-provider", Ok(Vec::new())),
            ClientProcessState::Unknown
        );
    }

    #[test]
    fn workbuddy_只认WorkBuddy不认旧CodeBuddy() {
        // 本工具的登录态写在 `%APPDATA%\WorkBuddy`，旧 CodeBuddy 用
        // `%APPDATA%\CodeBuddy` —— 解析到旧版会出现「切换成功但账号没变」。
        let spec = spec_of("workbuddy").expect("workbuddy 应有 spec");
        assert_eq!(spec.exe_names, &["WorkBuddy.exe"]);
        assert_eq!(spec.dir_keywords, &["workbuddy"]);
    }

    #[test]
    fn workbuddy_应能定位到安装好的客户端() {
        if !matching_dirs(&spec_of("workbuddy").expect("spec"))
            .iter()
            .any(|d| d.join("WorkBuddy.exe").is_file())
        {
            return;
        }
        let exe = client_exe("workbuddy").expect("应能定位到客户端");
        let name = exe.file_name().unwrap_or_default().to_string_lossy();
        assert_eq!(name, "WorkBuddy.exe", "解析到了 {exe:?}");
    }
}
