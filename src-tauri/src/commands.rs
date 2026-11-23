//! Tauri 命令层：UI 与后端之间的唯一入口。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chrono::TimeZone;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::core::config::{AppConfig, CloseAction};
use crate::core::logging::{self, LogEntry};
use crate::core::provider::{Account, CheckinStatus, ClaimState, CreditItem, Provider, Quota};
use crate::core::quota_history;
use crate::core::scheduler::{self, SchedulerState};
use crate::core::store::AccountStore;
use crate::notifications::{self, Inbox, NoticeKind};
use crate::providers::{minimax, qoder, trae};
use qoder::AuthSession;
use crate::providers::workbuddy;

/// 全局应用状态。
pub struct AppState {
    /// 账号池。Arc 包一层：providers 层 401 抢救路径的落盘钩子（POOL 全局）
    /// 要和这里持有同一份实例
    pub store: Arc<Mutex<AccountStore>>,
    /// 启动时账号池加载失败的原因（如文件损坏已备份）。正常启动为 None。
    pub store_warning: Option<String>,
    pub config: Mutex<AppConfig>,
    pub scheduler: Mutex<SchedulerState>,
    pub auth_sessions: Mutex<BTreeMap<String, AuthSession>>,
    pub inbox: Inbox,
    checkin_running: tokio::sync::Mutex<()>,
    sync_running: tokio::sync::Mutex<()>,
    pub providers: Vec<Arc<dyn Provider>>,
    /// 各平台适配器的具体类型（浏览器授权导入不走通用 trait，需要单独拿到）
    pub qoder: Arc<crate::providers::qoder::QoderProvider>,
    pub minimax: Arc<crate::providers::minimax::MiniMaxProvider>,
    pub workbuddy: Arc<crate::providers::workbuddy::WorkBuddyProvider>,
    pub trae: Arc<crate::providers::trae::TraeProvider>,
}

/// 账号池的全局句柄。providers 层的 401 抢救路径要读写池子，又不能反向依赖
/// commands 层（会循环引用），所以启动时把 Arc 挂到这里供钩子使用。
static POOL: std::sync::OnceLock<Arc<Mutex<AccountStore>>> = std::sync::OnceLock::new();

impl AppState {
    pub fn new() -> Self {
        let minimax = Arc::new(crate::providers::minimax::MiniMaxProvider::new());
        let qoder = Arc::new(crate::providers::qoder::QoderProvider::new());
        let workbuddy = Arc::new(crate::providers::workbuddy::WorkBuddyProvider::new());
        let trae = Arc::new(crate::providers::trae::TraeProvider::new());
        let list: Vec<Arc<dyn Provider>> = vec![
            workbuddy.clone(),
            minimax.clone(),
            trae.clone(),
            qoder.clone(),
            Arc::new(crate::providers::miaoshou::MiaoshouProvider::new()),
            Arc::new(crate::providers::zcode::ZcodeProvider::new()),
            Arc::new(crate::providers::doubaowork::DoubaoWorkProvider::new()),
        ];
        let (mut store, store_warning) = match AccountStore::load() {
            Ok(store) => (store, None),
            Err(err) => (AccountStore::default(), Some(err.to_string())),
        };
        // 旧版本把 MiniMax 登录态记录键的 hash 当账号 id（设备级，换号不变），
        // 会造成「导入新号覆盖旧号」。启动时把池里的旧时代条目归位一次（幂等）。
        crate::providers::minimax::migrate_device_key_ids(&mut store);
        let store = Arc::new(Mutex::new(store));
        // 401 抢救路径的凭据读写钩子（见 providers/minimax.rs::set_cred_hooks）
        crate::providers::minimax::set_cred_hooks(minimax_persist_hook, minimax_fetch_hook);
        let _ = POOL.set(store.clone());
        Self {
            store,
            store_warning,
            config: Mutex::new(AppConfig::load().unwrap_or_default()),
            scheduler: Mutex::new(SchedulerState::load().unwrap_or_default()),
            auth_sessions: Mutex::new(load_pending_auth()),
            inbox: Inbox::new(),
            checkin_running: tokio::sync::Mutex::new(()),
            sync_running: tokio::sync::Mutex::new(()),
            providers: list,
            qoder,
            minimax,
            workbuddy,
            trae,
        }
    }

    fn provider(&self, id: &str) -> Option<Arc<dyn Provider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }

    fn update_config(
        &self,
        update: impl FnOnce(&mut AppConfig) -> Result<(), String>,
    ) -> Result<AppConfig, String> {
        let mut config = self.config.lock().unwrap();
        let mut next = config.clone();
        update(&mut next)?;
        next.save().map_err(|err| err.to_string())?;
        *config = next.clone();
        Ok(next)
    }
}

/// 401 抢救刷新后的落盘钩子（providers/minimax.rs 经 set_cred_hooks 调进来）：
/// 只有池里已存在该账号时才回写，绝不凭空造条目。
fn minimax_persist_hook(provider_id: &str, account_id: &str, cred: &serde_json::Value) {
    let Some(pool) = POOL.get() else { return };
    let mut store = pool.lock().unwrap();
    if let Some(account) = store
        .list_of(provider_id)
        .into_iter()
        .find(|a| a.id == account_id)
    {
        let _ = store.upsert(account, cred);
    }
}

/// 401 抢救时先看一眼池里有没有别的任务刚刷新出的新凭据。
fn minimax_fetch_hook(provider_id: &str, account_id: &str) -> Option<serde_json::Value> {
    let pool = POOL.get()?;
    pool.lock()
        .unwrap()
        .credential(provider_id, account_id)
        .ok()
}

// ---------------------------------------------------------------------------
// 待完成授权会话的持久化
// ---------------------------------------------------------------------------

/// 读回上次没完成的设备授权会话（应用重启后恢复轮询用）。
///
/// 超过 30 分钟的会话直接丢弃：上游的设备码 / 授权 state 本身只有十几分钟
/// 有效期，留着的会话永远等不到确认，还会让启动时出现一条无意义的
/// 「等待授权」横幅（实测残留）。
fn load_pending_auth() -> BTreeMap<String, AuthSession> {
    let path = crate::core::paths::auth_pending_file();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    let Ok(map) = serde_json::from_str::<BTreeMap<String, AuthSession>>(&raw) else {
        return BTreeMap::new();
    };
    let now = chrono::Utc::now().timestamp();
    let live: BTreeMap<String, AuthSession> = map
        .clone()
        .into_iter()
        .filter(|(_, s)| now - s.created_at < 30 * 60)
        .collect();
    if live.len() != map.len() {
        // 有过期会话被清掉，顺手把落盘文件也更新
        if live.is_empty() {
            let _ = std::fs::remove_file(&path);
        } else if let Ok(text) = serde_json::to_string_pretty(&live) {
            let _ = crate::core::paths::atomic_write(&path, text.as_bytes());
        }
    }
    live
}

fn save_pending_auth(sessions: &BTreeMap<String, AuthSession>) {
    let path = crate::core::paths::auth_pending_file();
    if sessions.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Ok(text) = serde_json::to_string_pretty(sessions) {
        let _ = crate::core::paths::atomic_write(&path, text.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// 返回给前端的数据结构
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    pub accent: String,
    pub docs_url: String,
    /// 是否支持从本机客户端自动发现账号
    pub supports_discovery: bool,
    /// 是否支持浏览器授权导入账号（设备码 / OAuth 页）
    /// （显式 rename：serde 的 camelCase 会把它转成 supportsOauth，不是 OAuth）
    #[serde(rename = "supportsOAuth")]
    pub supports_oauth: bool,
    /// 浏览器授权后端是否已就绪。false = 按钮先展示「即将开放」。
    #[serde(rename = "oauthReady")]
    pub oauth_ready: bool,
    /// 是否已配置账号
    pub configured: bool,
    /// 本机是否装了该 agent 的客户端
    pub has_client: bool,
    /// 客户端可执行文件路径
    pub client_exe: Option<String>,
    /// 是否支持自动领取（false = 只展示 + 提醒，不调用领取接口）
    pub supports_claim: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub account: Account,
    pub provider_name: String,
    pub accent: String,
    pub status: Option<CheckinStatus>,
    pub quota: Option<Quota>,
    pub quota_error: Option<String>,
    pub error: Option<String>,
    pub today_log: Option<LogEntry>,
    /// 是否为该 agent 的当前账号
    pub is_active: bool,
    /// 客户端当前实际登录的是不是这个账号
    pub is_client_login: bool,
    /// 客户端数据目录（项目/会话都在这里）
    pub data_dir: Option<String>,
    /// 本地项目数
    pub project_count: usize,
    /// 本地会话数
    pub session_count: usize,
    /// 积分是否低于预警阈值
    pub is_low: bool,
    /// 积分预警阈值
    pub alert_threshold: u32,
    /// 最近 7 天的积分快照（升序），用于画趋势
    pub trend: Vec<QuotaPoint>,
    /// Qoder 每日领取的本地记录（平台逐包明细需要网页登录态，见 docs）。
    /// 其他平台为空。
    #[serde(default)]
    pub tracked_grants: Vec<CreditItem>,
    /// 是否支持自动领取（false = 只展示 + 提醒，不调用领取接口）
    pub supports_claim: bool,
}

/// 趋势上的一个点。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaPoint {
    pub timestamp: String,
    pub remaining: f64,
}

/// 单个 agent 的调度配置（前端用来渲染它自己的自动签到开关）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentScheduleView {
    pub enabled: bool,
    pub start_minute: u32,
    pub end_minute: u32,
    pub account_count: usize,
    pub today_claimed: usize,
    pub today_claimable: usize,
    /// 该 agent 的数据自动同步间隔（分钟）
    pub refresh_interval_minutes: u32,
    /// 客户端当前实际登录的账号（None = 读不到 / 客户端没登录）
    pub client_account: Option<ClientAccountView>,
    /// 能不能靠「写凭据文件」给这个客户端换账号
    pub switchable: bool,
    /// 换号时是否同步客户端本地聊天记录（WorkBuddy / Qoder 有此开关）
    pub chat_sync_enabled: bool,
    /// 这个平台的客户端是否支持聊天记录同步（决定开关显不显示）
    pub chat_sync_supported: bool,
}

/// 客户端当前登录的账号。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAccountView {
    pub account_id: String,
    pub label: String,
    /// 这个账号在不在我们的账号池里（不在说明是客户端自己登的号）
    pub in_pool: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub accounts: Vec<AccountView>,
    pub providers: Vec<ProviderView>,
    pub today_points: i64,
    pub claimed_count: usize,
    pub total_count: usize,
    /// 签到总闸
    pub scheduler_enabled: bool,
    /// 自动同步（积分 / 状态 / 资料）总开关
    pub sync_enabled: bool,
    /// 每个 agent 自己的调度配置（前端按 agent 渲染各自的开关）
    pub agents: BTreeMap<String, AgentScheduleView>,
    /// 每个账号今天的计划执行时刻（分钟）
    pub plans: BTreeMap<String, u32>,
    /// 应用数据目录（账号池 / 配置 / 日志都在这里）
    pub data_dir: String,
    /// 账号池加载失败等需要让用户知道的警告（正常为 None）
    #[serde(default)]
    pub store_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResult {
    pub account_id: String,
    pub provider: String,
    pub label: String,
    /// `success` / `already` / `failed` / `skipped`
    pub status: String,
    pub points: i64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedClientAccount {
    pub account: Account,
    pub already_added: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthChallenge {
    pub session_id: String,
    pub auth_url: String,
    /// 发起授权的 provider
    pub provider: String,
    /// 授权码有效期（秒）；前端据此显示倒计时
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// 命令
// ---------------------------------------------------------------------------

/// 从签到流水里解析 Qoder 每日领取的有效期（默认 30 天）。
fn qoder_valid_days(message: &str) -> i64 {
    if let Some(idx) = message.find(" 天有效") {
        let digits: String = message[..idx]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if let Ok(days) = digits.parse::<i64>() {
            if days > 0 {
                return days;
            }
        }
    }
    30
}

/// 用本地签到日志回填 Qoder 每日领取批次。
///
/// 平台逐包明细接口需要网页登录态（见 docs/PROJECT-STATUS.md），设备 token 拿不到；
/// 这里只能记录**通过 CheckinBox 领取过**的批次：每天一条，到期 = 领取时间 + 有效期。
/// 同一账号同一天多条成功日志只保留一条；超过 3 天以前到期的批次不再展示。
fn qoder_tracked_grants(logs: &[LogEntry], account: &Account, now_ms: i64) -> Vec<CreditItem> {
    const DAY_MS: i64 = 86_400_000;
    let mut seen_days = HashSet::new();
    let mut out = Vec::new();
    for entry in logs.iter().filter(|e| {
        e.provider == "qoder" && e.account_id == account.id && e.status == "success" && e.points > 0
    }) {
        if !seen_days.insert(entry.date.clone()) {
            continue;
        }
        let Some(granted_at_ms) =
            chrono::NaiveDateTime::parse_from_str(&entry.timestamp, "%Y-%m-%d %H:%M:%S")
                .ok()
                .and_then(|dt| dt.and_local_timezone(chrono::Local).single())
                .map(|dt| dt.timestamp_millis())
        else {
            continue;
        };
        let expire_at_ms = granted_at_ms + qoder_valid_days(&entry.message) * DAY_MS;
        if expire_at_ms <= now_ms - 3 * DAY_MS {
            continue;
        }
        out.push(CreditItem {
            credit_type: "daily".to_string(),
            granted: entry.points as f64,
            consumed: 0.0,
            remaining: entry.points as f64,
            granted_at_ms,
            expire_at_ms,
            package_name: String::new(),
            refresh_at_ms: 0,
        });
    }
    out.sort_by(|a, b| b.granted_at_ms.cmp(&a.granted_at_ms));
    out
}

/// 汇总所有账号的今日状态。
#[tauri::command]
pub async fn overview(state: State<'_, AppState>) -> Result<Overview, String> {
    let store = state.store.lock().unwrap().clone();
    let config = state.config.lock().unwrap().clone();
    let scheduler = state.scheduler.lock().unwrap().clone();
    let logs = logging::recent(1).unwrap_or_default();
    // Qoder 的逐包明细只能从本地领取记录回填：多读 35 天日志（30 天有效期 + 缓冲）。
    let grant_logs = if store
        .list()
        .iter()
        .any(|account| account.provider == "qoder")
    {
        logging::recent(35).unwrap_or_default()
    } else {
        Vec::new()
    };
    let now_ms = chrono::Local::now().timestamp_millis();

    let mut accounts: Vec<AccountView> = Vec::new();
    let mut today_points = 0i64;
    let mut claimed_count = 0usize;
    // 需要改成真实昵称的账号（循环里只收集，最后统一落盘）
    let mut relabel: Vec<Account> = Vec::new();

    // 客户端当前实际登录的账号（只读检测；先算好，账号行与 agent 视图共用，
    // 避免每个账号重复解一次客户端登录态文件）。
    // ⚠️ MiniMax 走 token 实测（client_session）：客户端配置里的 sharedUser
    // 在外部切换后是陈旧的，信它会把身份判错、污染账号池（2026-10-25 踩坑）。
    let mut client_login: BTreeMap<String, Option<ClientAccountView>> = BTreeMap::new();
    for provider in state.providers.iter() {
        let detected = if provider.id() == "minimax" {
            crate::providers::minimax::client_session()
                .await
                .map(|(id, name, _)| (id, name))
        } else {
            crate::core::client_switch::detect(provider.id())
                .ok()
                .flatten()
                .map(|d| (d.account_id, d.label))
        };
        client_login.insert(
            provider.id().to_string(),
            detected.map(|(mut account_id, label)| {
                if provider.id() == "workbuddy" {
                    if let Some(account) = workbuddy_pool_account(&store, &account_id) {
                        account_id = account.id;
                    }
                } else if provider.id() == "qoder" {
                    if let Some(legacy) = qoder_legacy_pool_id(&store, &account_id) {
                        account_id = legacy;
                    }
                }
                ClientAccountView {
                    in_pool: store.contains(provider.id(), &account_id),
                    account_id,
                    label,
                }
            }),
        );
    }

    // 网络部分并发化：每个账号一个任务（昵称 + 状态 + 积分同时进行），
    // 7 个账号 14 次串行请求（3-4 秒）变成「最慢的一个账号」的时间（~400ms）。
    // 单个账号失败不影响其他账号。
    //
    // 凭据保鲜（MiniMax 刷新）**不放进任务**：它要读写账号池，必须在主循环里做，
    // 这样才能「加锁 → 重读池 → 刷新 → 落盘 → 解锁」，让并发调用方拿到新 RT。
    struct Fetched {
        account: Account,
        display_label: Option<String>,
        status: Option<CheckinStatus>,
        error: Option<String>,
        quota: Option<Quota>,
        quota_error: Option<String>,
    }
    let mut fetch_tasks = Vec::new();
    for account in store.list() {
        let Some(provider) = state.provider(&account.provider) else {
            continue;
        };
        let cred = match store.credential(&account.provider, &account.id) {
            Ok(c) => c,
            // 单个账号凭据损坏不应让整个界面空白：跳过它，其余照常展示
            Err(_) => continue,
        };
        // 当前登录的捕获客户端最新 token；非当前登录的临过期自动刷新（内部落盘）
        let cred = ensure_fresh_cred(&state, &account, &cred).await;

        fetch_tasks.push(tokio::spawn(async move {
            // 兜底 label（`Qoder 01a1348c-3fc` 这种 id 前缀）才去换真实昵称，
            // 避免每 45 秒给每个账号多打一次资料接口。换到就落盘，之后不用再查。
            let mut display_label: Option<String> = None;
            if account.label_is_fallback() {
                if let Ok(Some(profile)) = provider.profile(&account, &cred).await {
                    if let Some(name) = profile
                        .name
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        display_label = Some(name.to_string());
                    }
                }
            }

            let (status, error) = match provider.status(&account, &cred).await {
                Ok(s) => (Some(s), None),
                Err(e) => (None, Some(e.to_string())),
            };

            // 积分与签到是两个独立请求：积分失败不影响签到状态展示
            let (quota, quota_error) = match provider.quota(&account, &cred).await {
                Ok(q) => (Some(q), None),
                Err(e) => (None, Some(e.to_string())),
            };

            Fetched {
                account,
                display_label,
                status,
                error,
                quota,
                quota_error,
            }
        }));
    }

    for task in fetch_tasks {
        let fetched = match task.await {
            Ok(f) => f,
            Err(_) => continue, // 任务 panic（不应发生）：跳过该账号
        };
        let account = &fetched.account;
        let provider = match state.provider(&account.provider) {
            Some(p) => p,
            None => continue,
        };

        let mut display_account = account.clone();
        if let Some(name) = &fetched.display_label {
            display_account.label = name.clone();
            relabel.push(display_account.clone());
        }

        if let Some(s) = &fetched.status {
            if s.state == ClaimState::Claimed {
                claimed_count += 1;
            }
            today_points += if s.state == ClaimState::Claimed {
                s.points
            } else {
                0
            };
        }

        // 落一条积分快照（趋势图用）。失败不致命。
        if let Some(q) = &fetched.quota {
            let _ = quota_history::append(&quota_history::QuotaSnapshot::new(
                &account.provider,
                &account.id,
                &account.label,
                q.total_remaining,
                q.total_granted,
                q.total_consumed,
            ));
        }

        let today_log = logs
            .iter()
            .find(|l| l.account_id == account.id && l.provider == account.provider)
            .cloned();

        let is_active = config.active_of(&account.provider).as_deref() == Some(account.id.as_str());
        let is_client_login = client_login
            .get(&account.provider)
            .and_then(|c| c.as_ref())
            .map(|c| c.account_id == account.id)
            .unwrap_or(false);
        let (data_dir, project_count, session_count) =
            match crate::core::launcher::account_stats(&account.provider) {
                Some((p, s)) => (
                    crate::core::launcher::data_dir(&account.provider)
                        .map(|d| d.to_string_lossy().to_string()),
                    p,
                    s,
                ),
                None => (None, 0, 0),
            };
        let threshold = config.alert_threshold_of(&account.provider);
        let trend = quota_history::recent_of(&account.provider, &account.id, 7)
            .unwrap_or_default()
            .into_iter()
            .map(|s| QuotaPoint {
                timestamp: s.timestamp,
                remaining: s.remaining,
            })
            .collect();
        // 积分是否低于预警阈值
        let is_low = fetched
            .quota
            .as_ref()
            .map(|q| q.total_remaining < threshold as f64)
            .unwrap_or(false);

        // Qoder 每日 100 的逐包到期：平台接口只给聚合值（expiresAt=9999），
        // 网页端逐包明细需要网页登录态；这里用本地签到日志回填（仅记录本工具领过的批次）。
        let tracked_grants = if account.provider == "qoder" {
            qoder_tracked_grants(&grant_logs, &display_account, now_ms)
        } else {
            Vec::new()
        };

        accounts.push(AccountView {
            provider_name: provider.display_name().to_string(),
            accent: provider.accent().to_string(),
            account: display_account,
            status: fetched.status,
            quota: fetched.quota,
            quota_error: fetched.quota_error,
            error: fetched.error,
            today_log,
            is_active,
            is_client_login,
            data_dir,
            project_count,
            session_count,
            is_low,
            alert_threshold: threshold,
            trend,
            tracked_grants,
            supports_claim: provider.supports_claim(),
        });
    }

    // 把换到的真实昵称落盘（只写变化的，且整体一次写完）
    if !relabel.is_empty() {
        let mut guard = state.store.lock().unwrap();
        for account in &relabel {
            let _ = guard.touch(account.clone());
        }
    }

    // 平台按用户拖拽的自定义顺序排列（未配置的按注册顺序排在后面）
    let ordered_ids =
        config.sort_provider_ids(state.providers.iter().map(|p| p.id().to_string()).collect());

    let provider_views = ordered_ids
        .iter()
        .filter_map(|id| state.provider(id))
        .map(|p| {
            let exe = crate::core::launcher::client_exe(p.id());
            ProviderView {
                id: p.id().to_string(),
                name: p.display_name().to_string(),
                accent: p.accent().to_string(),
                docs_url: p.docs_url().to_string(),
                supports_discovery: matches!(
                    p.id(),
                    "minimax" | "miaoshou" | "workbuddy" | "zcode" | "qoder" | "trae" | "doubaowork"
                ),
                supports_oauth: matches!(p.id(), "qoder" | "minimax" | "workbuddy" | "trae"),
                oauth_ready: true,
                configured: !store.list_of(p.id()).is_empty(),
                has_client: exe.is_some(),
                client_exe: exe.map(|p| p.to_string_lossy().to_string()),
                supports_claim: p.supports_claim(),
            }
        })
        .collect();

    // 每个 agent 自己的调度配置
    let mut agents_view: BTreeMap<String, AgentScheduleView> = BTreeMap::new();
    for provider in state.providers.iter() {
        let cfg = config.scheduler.agent(provider.id());
        let list = store.list_of(provider.id());
        let claimed = accounts
            .iter()
            .filter(|a| {
                a.account.provider == provider.id()
                    && a.status
                        .as_ref()
                        .map(|s| s.state == ClaimState::Claimed)
                        .unwrap_or(false)
            })
            .count();
        let claimable = accounts
            .iter()
            .filter(|a| {
                a.account.provider == provider.id()
                    && a.status
                        .as_ref()
                        .map(|s| s.state == ClaimState::Claimable)
                        .unwrap_or(false)
            })
            .count();
        agents_view.insert(
            provider.id().to_string(),
            AgentScheduleView {
                enabled: cfg.enabled,
                start_minute: cfg.start_minute,
                end_minute: cfg.end_minute,
                account_count: list.len(),
                today_claimed: claimed,
                today_claimable: claimable,
                refresh_interval_minutes: config.refresh_interval_of(provider.id()),
                // 客户端当前登录的账号（只读，读不到就是 None）
                client_account: client_login.get(provider.id()).cloned().flatten(),
                switchable: crate::core::client_switch::is_switchable(provider.id()),
                chat_sync_enabled: cfg.chat_sync_enabled,
                chat_sync_supported: crate::core::chat_sync::supports(provider.id()),
            },
        );
    }

    let plans = scheduler
        .accounts
        .iter()
        .map(|(k, v)| (k.clone(), v.scheduled_minute))
        .collect();

    let data_dir = crate::core::paths::data_dir().to_string_lossy().to_string();

    Ok(Overview {
        total_count: accounts.len(),
        claimed_count,
        today_points,
        accounts,
        providers: provider_views,
        scheduler_enabled: config.scheduler.enabled,
        sync_enabled: config.scheduler.sync_enabled,
        agents: agents_view,
        plans,
        data_dir,
        store_warning: state.store_warning.clone(),
    })
}

/// 对单个账号执行签到。
#[tauri::command]
pub async fn checkin_account(
    state: State<'_, AppState>,
    provider_id: String,
    account_id: String,
) -> Result<AccountResult, String> {
    let _running = state
        .checkin_running
        .try_lock()
        .map_err(|_| "正在签到，请稍后再试")?;
    let Some(provider) = state.provider(&provider_id) else {
        return Err(format!("未知平台：{provider_id}"));
    };
    let store = state.store.lock().unwrap().clone();
    let Some(account) = store
        .list_of(&provider_id)
        .into_iter()
        .find(|a| a.id == account_id)
    else {
        return Err(format!("账号不存在：{account_id}"));
    };
    let cred = store
        .credential(&provider_id, &account_id)
        .map_err(|e| e.to_string())?;
    let cred = ensure_fresh_cred(&state, &account, &cred).await;

    let result = run_checkin(provider.as_ref(), &account, &cred).await;
    record_result(&account, &result);

    // 手动执行后清掉「今日已签」标记，交给调度器重新判定状态。
    if result.status != "failed" {
        let mut sched = state.scheduler.lock().unwrap();
        sched.clear_done(&AccountStore::key(&provider_id, &account_id));
        let _ = sched.save();
    }
    Ok(result)
}

/// 对所有账号执行签到。
#[tauri::command]
pub async fn checkin_all(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<TaskSummary, String> {
    checkin_all_inner(&app, &state).await
}

/// 对所有账号执行签到（供托盘菜单等非命令入口复用）。
pub async fn checkin_all_inner(app: &AppHandle, state: &AppState) -> Result<TaskSummary, String> {
    let _running = state
        .checkin_running
        .try_lock()
        .map_err(|_| "正在签到，请稍后再试")?;
    let store = state.store.lock().unwrap().clone();
    let mut out = Vec::new();
    for account in store.list() {
        let Some(provider) = state.provider(&account.provider) else {
            continue;
        };
        // 只展示 + 提醒的平台（Zcode）不进「一键全部签到」
        if !provider.supports_claim() {
            continue;
        }
        let cred = match store.credential(&account.provider, &account.id) {
            Ok(c) => c,
            Err(e) => {
                let result = AccountResult {
                    account_id: account.id.clone(),
                    provider: account.provider.clone(),
                    label: account.label.clone(),
                    status: "failed".into(),
                    points: 0,
                    message: e.to_string(),
                };
                record_result(&account, &result);
                out.push(result);
                continue;
            }
        };
        let cred = ensure_fresh_cred(state, &account, &cred).await;
        let result = run_checkin(provider.as_ref(), &account, &cred).await;
        record_result(&account, &result);
        out.push(result);
    }
    let _ = app.emit("accounts-changed", ());
    Ok(checkin_summary(&out))
}

#[derive(Serialize)]
pub struct TaskSummary {
    pub kind: NoticeKind,
    pub message: String,
}

fn checkin_summary(results: &[AccountResult]) -> TaskSummary {
    if results.is_empty() {
        return TaskSummary {
            kind: NoticeKind::Warn,
            message: "暂无可签到的账号。".into(),
        };
    }
    let success = results.iter().filter(|r| r.status == "success").count();
    let already = results.iter().filter(|r| r.status == "already").count();
    let failed = results.iter().filter(|r| r.status == "failed").count();
    let skipped = results.len() - success - already - failed;
    let mut message =
        format!("成功 {success} 个，今日已签 {already} 个，跳过 {skipped} 个，失败 {failed} 个。");
    if failed > 0 {
        message.push_str("失败原因可在签到记录中查看。");
    }
    TaskSummary {
        kind: if failed > 0 || skipped > 0 {
            NoticeKind::Warn
        } else {
            NoticeKind::Ok
        },
        message,
    }
}

/// 刷新单个账号的积分（不碰签到状态）。
#[tauri::command]
pub async fn refresh_quota(
    state: State<'_, AppState>,
    provider_id: String,
    account_id: String,
) -> Result<Quota, String> {
    let provider = state
        .provider(&provider_id)
        .ok_or_else(|| format!("未知平台：{provider_id}"))?;
    let store = state.store.lock().unwrap().clone();
    let cred = store
        .credential(&provider_id, &account_id)
        .map_err(|e| e.to_string())?;
    let account = store
        .list_of(&provider_id)
        .into_iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("账号不存在：{account_id}"))?;
    let quota = provider
        .quota(&account, &cred)
        .await
        .map_err(|e| e.to_string())?;
    // 用户主动刷新看到的最新积分也应该进趋势图，否则曲线和界面显示对不上
    let _ = quota_history::append(&quota_history::QuotaSnapshot::new(
        &account.provider,
        &account.id,
        &account.label,
        quota.total_remaining,
        quota.total_granted,
        quota.total_consumed,
    ));
    Ok(quota)
}

/// 刷新全部账号的积分。
#[tauri::command]
pub async fn refresh_all_quotas(
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, Quota)>, String> {
    let store = state.store.lock().unwrap().clone();
    let mut out = Vec::new();
    for account in store.list() {
        let Some(provider) = state.provider(&account.provider) else {
            continue;
        };
        let Ok(cred) = store.credential(&account.provider, &account.id) else {
            continue;
        };
        if let Ok(q) = provider.quota(&account, &cred).await {
            out.push((account.provider.clone(), account.id.clone(), q));
        }
    }
    Ok(out)
}

/// WorkBuddy 积分明细：某官方分组下的资源包（有效期内 / 已过期，分页）。
#[tauri::command]
pub async fn workbuddy_credit_packages(
    state: State<'_, AppState>,
    account_id: String,
    kind: String,
    expired: bool,
    page: u32,
) -> Result<crate::providers::workbuddy::CreditPackagePage, String> {
    let store = state.store.lock().unwrap().clone();
    let cred = store
        .credential("workbuddy", &account_id)
        .map_err(|e| e.to_string())?;
    state
        .workbuddy
        .credit_packages(&cred, &kind, expired, page)
        .await
        .map_err(|e| e.to_string())
}

/// WorkBuddy 近 30 天消耗明细（最近 5 条）。
#[tauri::command]
pub async fn workbuddy_credit_usage(
    state: State<'_, AppState>,
    account_id: String,
) -> Result<crate::providers::workbuddy::CreditUsagePage, String> {
    let store = state.store.lock().unwrap().clone();
    let cred = store
        .credential("workbuddy", &account_id)
        .map_err(|e| e.to_string())?;
    state
        .workbuddy
        .credit_usage(&cred)
        .await
        .map_err(|e| e.to_string())
}

/// 界面上的本机导入读取客户端。WorkBuddy 的 Cockpit 账号库只用于批量导入。
async fn discover_client_accounts(
    provider: &dyn Provider,
) -> anyhow::Result<Vec<(Account, serde_json::Value)>> {
    if provider.id() == "workbuddy" {
        return Ok(crate::core::client_switch::workbuddy_client_login()
            .into_iter()
            .collect());
    }
    provider.discover().await
}

/// Re-importing Qoder must refresh its display name from the profile API:
/// `auth.v1.dat` can retain the old nickname after it changes on the account.
/// If the profile lookup is unavailable, keep an existing useful label instead
/// of replacing it with the `Qoder <id>` fallback.
async fn refresh_imported_account_label(
    provider: &dyn Provider,
    account: &mut Account,
    cred: &serde_json::Value,
    previous_label: Option<&str>,
) {
    if account.provider != "qoder" {
        return;
    }
    if let Ok(Some(profile)) = provider.profile(account, cred).await {
        if let Some(name) = profile
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            account.label = name.to_string();
            return;
        }
    }
    if account.label_is_fallback() {
        if let Some(previous) = previous_label
            .map(str::trim)
            .filter(|label| !label.is_empty() && !label.starts_with("Qoder "))
        {
            account.label = previous.to_string();
        }
    }
}

/// Trae 的签到设备号分配：已有合法号沿用，否则用真机号/同源衍生号，
/// 保证同一设备上的多个 Trae 账号不会撞 9095。
fn assign_trae_checkin_device_id(
    existing: &[(Account, serde_json::Value)],
    account: &Account,
    cred: &mut serde_json::Value,
) {
    if let Some((_, old)) = existing.iter().find(|(item, _)| item.id == account.id) {
        if let Some(id) = old["checkin_device_id"]
            .as_str()
            .filter(|id| crate::providers::trae::is_valid_device_id(id))
        {
            cred["checkin_device_id"] = serde_json::json!(id);
            cred["device_source"] = old
                .get("device_source")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            return;
        }
    }
    let used: Vec<String> = existing
        .iter()
        .filter_map(|(_, old)| {
            old["checkin_device_id"]
                .as_str()
                .filter(|id| crate::providers::trae::is_valid_device_id(id))
                .map(str::to_string)
        })
        .collect();
    let real = cred["login_device_id"].as_str().unwrap_or("");
    let prefer_real = !used.iter().any(|id| id == real);
    let id = crate::providers::trae::assign_checkin_device_id(
        &account.id,
        real,
        &used,
        prefer_real,
    );
    cred["checkin_device_id"] = serde_json::json!(id);
}

/// 从客户端读取一次登录态，返回本次已写入或更新的账号。
#[tauri::command]
pub async fn import_client_accounts(
    state: State<'_, AppState>,
    provider_id: String,
) -> Result<Vec<ImportedClientAccount>, String> {
    let Some(provider) = state.provider(&provider_id) else {
        return Err(format!("未知平台：{provider_id}"));
    };
    let found = discover_client_accounts(provider.as_ref())
        .await
        .map_err(|e| e.to_string())?;
    if found.is_empty() {
        return Ok(Vec::new());
    }
    let previous_labels: HashMap<String, String> = state
        .store
        .lock()
        .unwrap()
        .list_of(&provider_id)
        .into_iter()
        .map(|account| (account.id, account.label))
        .collect();

    // Trae：一台设备一天只能签一个账号，导入时给每个账号分配唯一的签到设备号。
    // 已在池里的账号沿用原设备号，避免把已经绑定好的号换掉。
    let existing_trae: Vec<(Account, serde_json::Value)> = if provider_id == "trae" {
        let store = state.store.lock().unwrap();
        store
            .list_of("trae")
            .into_iter()
            .filter_map(|account| {
                store
                    .credential("trae", &account.id)
                    .ok()
                    .map(|cred| (account, cred))
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut used_devices: Vec<String> = existing_trae
        .iter()
        .filter_map(|(_, cred)| {
            cred["checkin_device_id"]
                .as_str()
                .filter(|id| crate::providers::trae::is_valid_device_id(id))
                .map(str::to_string)
        })
        .collect();

    let mut refreshed = Vec::with_capacity(found.len());
    for (mut account, mut cred) in found {
        let account_id = account.id.clone();
        if provider_id == "trae" {
            let keep = existing_trae
                .iter()
                .find(|(existing, _)| existing.id == account.id)
                .and_then(|(_, old)| old["checkin_device_id"].as_str())
                .filter(|id| crate::providers::trae::is_valid_device_id(id));
            let device_id = match keep {
                Some(id) => id.to_string(),
                None => {
                    let real = cred["login_device_id"].as_str().unwrap_or("");
                    let prefer_real = !used_devices.iter().any(|used| used == real);
                    crate::providers::trae::assign_checkin_device_id(
                        &account.id,
                        real,
                        &used_devices,
                        prefer_real,
                    )
                }
            };
            cred["checkin_device_id"] = serde_json::json!(device_id);
            if !used_devices.iter().any(|used| used == &device_id) {
                used_devices.push(device_id);
            }
        }
        refresh_imported_account_label(
            provider.as_ref(),
            &mut account,
            &cred,
            previous_labels.get(&account_id).map(String::as_str),
        )
        .await;
        refreshed.push((account, cred));
    }
    let mut store = state.store.lock().unwrap();
    let mut imported = Vec::with_capacity(refreshed.len());
    for (mut account, cred) in refreshed {
        if provider_id == "workbuddy" {
            reuse_workbuddy_pool_id(&store, &mut account);
        } else if provider_id == "qoder" {
            reuse_qoder_pool_id(&store, &mut account);
        }
        let already_added = store.contains(&account.provider, &account.id);
        store.upsert(account.clone(), &cred).map_err(|e| e.to_string())?;
        imported.push(ImportedClientAccount {
            account,
            already_added,
        });
    }
    Ok(imported)
}

/// 发起浏览器授权导入（Qoder / MiniMax / WorkBuddy）：返回一个需要在浏览器里确认的地址。
#[tauri::command]
pub async fn begin_device_auth(
    state: State<'_, AppState>,
    provider_id: String,
) -> Result<AuthChallenge, String> {
    let now = chrono::Utc::now().timestamp();
    let session = match provider_id.as_str() {
        "qoder" => state
            .qoder
            .begin_authorization(&provider_id)
            .map_err(|e| e.to_string())?,
        "minimax" => {
            let d = state
                .minimax
                .begin_device_authorization()
                .await
                .map_err(|e| e.to_string())?;
            AuthSession {
                id: uuid::Uuid::new_v4().to_string(),
                provider: provider_id.clone(),
                auth_url: d.auth_url,
                verifier: d.code_verifier,
                nonce: d.poll_code,
                machine_id: String::new(),
                created_at: now,
                extra: serde_json::json!({
                    "poll_param": d.poll_param,
                    "interval": d.interval_secs,
                    "expires_in": d.expires_in,
                }),
            }
        }
        "workbuddy" => {
            let (st, url) = state
                .workbuddy
                .begin_authorization()
                .await
                .map_err(|e| e.to_string())?;
            AuthSession {
                id: uuid::Uuid::new_v4().to_string(),
                provider: provider_id.clone(),
                auth_url: url,
                verifier: String::new(),
                nonce: st,
                machine_id: String::new(),
                created_at: now,
                extra: serde_json::json!({ "workbuddy_auth": true }),
            }
        }
        "trae" => state
            .trae
            .begin_authorization()
            .await
            .map_err(|e| e.to_string())?,
        other => return Err(format!("{other} 不支持浏览器授权导入")),
    };
    let challenge = AuthChallenge {
        session_id: session.id.clone(),
        auth_url: session.auth_url.clone(),
        provider: session.provider.clone(),
        expires_in_secs: session.extra.get("expires_in").and_then(|v| v.as_u64()),
    };
    {
        let mut sessions = state.auth_sessions.lock().unwrap();
        sessions.insert(session.id.clone(), session);
        save_pending_auth(&sessions);
    }
    Ok(challenge)
}

/// 取当前所有待完成的授权会话（前端启动时恢复轮询用）。
#[tauri::command]
pub async fn pending_auth(state: State<'_, AppState>) -> Result<Vec<AuthChallenge>, String> {
    let sessions = state.auth_sessions.lock().unwrap().clone();
    Ok(sessions
        .into_values()
        .map(|s| AuthChallenge {
            session_id: s.id,
            auth_url: s.auth_url,
            provider: s.provider,
            expires_in_secs: s.extra.get("expires_in").and_then(|v| v.as_u64()),
        })
        .collect())
}

/// 轮询浏览器授权结果；`None` 表示用户还没确认。
#[tauri::command]
pub async fn poll_device_auth(
    state: State<'_, AppState>,
    provider_id: String,
    session_id: String,
) -> Result<Option<Account>, String> {
    let session = {
        let sessions = state.auth_sessions.lock().unwrap();
        sessions.get(&session_id).cloned()
    };
    let Some(session) = session else {
        return Err("授权会话已过期，请重新发起".into());
    };
    if session.provider != provider_id {
        return Err("授权会话的平台不一致，请重新发起".into());
    }

    let polled = match session.provider.as_str() {
        "qoder" => state.qoder.poll_authorization(&session).await,
        "minimax" => {
            let poll_param = session.extra["poll_param"]
                .as_str()
                .unwrap_or("device_code");
            state
                .minimax
                .poll_device_authorization(&session.verifier, &session.nonce, poll_param)
                .await
        }
        "workbuddy" => {
            let legacy = session.extra["workbuddy_auth"].as_bool() != Some(true);
            state
                .workbuddy
                .poll_authorization(&session.nonce, legacy)
                .await
        }
        "trae" => state.trae.poll_authorization(&session).await,
        other => return Err(format!("{other} 不支持浏览器授权导入")),
    };

    match polled {
        Ok(Some((mut account, mut cred))) => {
            // 账号归属以发起时的 provider 为准
            account.provider = provider_id.clone();
            let previous_label = state
                .store
                .lock()
                .unwrap()
                .list_of(&provider_id)
                .into_iter()
                .find(|existing| existing.id == account.id)
                .map(|existing| existing.label);
            if let Some(provider) = state.provider(&provider_id) {
                refresh_imported_account_label(
                    provider.as_ref(),
                    &mut account,
                    &cred,
                    previous_label.as_deref(),
                )
                .await;
            }
            if provider_id == "trae" {
                let existing: Vec<(Account, serde_json::Value)> = {
                    let store = state.store.lock().unwrap();
                    store
                        .list_of("trae")
                        .into_iter()
                        .filter_map(|item| {
                            store
                                .credential("trae", &item.id)
                                .ok()
                                .map(|old| (item, old))
                        })
                        .collect()
                };
                assign_trae_checkin_device_id(&existing, &account, &mut cred);
            }
            let mut store = state.store.lock().unwrap();
            if provider_id == "workbuddy" {
                reuse_workbuddy_pool_id(&store, &mut account);
            } else if provider_id == "qoder" {
                reuse_qoder_pool_id(&store, &mut account);
            }
            store
                .upsert(account.clone(), &cred)
                .map_err(|e| e.to_string())?;
            {
                let mut sessions = state.auth_sessions.lock().unwrap();
                sessions.remove(&session_id);
                save_pending_auth(&sessions);
            }
            Ok(Some(account))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// 从账号池移除账号。
#[tauri::command]
pub async fn remove_account(
    state: State<'_, AppState>,
    provider_id: String,
    account_id: String,
) -> Result<Vec<Account>, String> {
    {
        let mut store = state.store.lock().unwrap();
        store
            .remove(&provider_id, &account_id)
            .map_err(|e| e.to_string())?;
    }
    // 删掉的是「当前账号」的话，同步清掉引用 —— 否则 config 里留下指向
    // 已删账号的野指针，界面的「当前账号」徽标永远匹配不上
    {
        let mut config = state.config.lock().unwrap();
        if config.active_of(&provider_id).as_deref() == Some(account_id.as_str()) {
            config.active_accounts.remove(&provider_id);
            config.save().map_err(|e| e.to_string())?;
        }
    }
    Ok(state.store.lock().unwrap().list())
}

/// 保存侧栏 agent 的拖拽顺序（校验：必须是已注册平台的排列）。
#[tauri::command]
pub async fn set_agent_order(
    state: State<'_, AppState>,
    order: Vec<String>,
) -> Result<AppConfig, String> {
    let known: Vec<&str> = state.providers.iter().map(|p| p.id()).collect();
    for id in &order {
        if !known.contains(&id.as_str()) {
            return Err(format!("未知平台：{id}"));
        }
    }
    let unique = order.len()
        == order
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
    if !unique {
        return Err("顺序里有重复的平台".into());
    }
    state.update_config(|config| {
        config.agent_order = order;
        Ok(())
    })
}

/// 读取配置。
#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    Ok(state.config.lock().unwrap().clone())
}

/// 写回配置。
#[tauri::command]
pub async fn set_config(
    state: State<'_, AppState>,
    config: AppConfig,
) -> Result<AppConfig, String> {
    // 校验每个 agent 自己的时间窗
    for (id, cfg) in &config.scheduler.agents {
        if !cfg.is_valid() {
            return Err(format!("{id} 的调度时间窗不合法（起必须早于止）"));
        }
        if cfg.refresh_interval_minutes == 0 {
            return Err(format!("{id} 的同步间隔不合法（至少 1 分钟）"));
        }
    }
    state.update_config(|current| {
        *current = config;
        Ok(())
    })
}

/// 设置点击窗口 × 时的行为（设置页用）。
#[tauri::command]
pub async fn set_close_action(
    state: State<'_, AppState>,
    action: CloseAction,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.close_action = action;
        Ok(())
    })
}

/// 关闭确认框的选择结果。
///
/// `remember` 为 true 时把这次选择写进配置（下次不再询问）；
/// 否则只执行这一次，配置仍是「每次询问」。
#[tauri::command]
pub async fn resolve_close_action(
    app: AppHandle,
    state: State<'_, AppState>,
    action: CloseAction,
    remember: bool,
) -> Result<(), String> {
    if remember {
        state.update_config(|config| {
            config.close_action = action;
            Ok(())
        })?;
    }
    match action {
        CloseAction::Tray => {
            if let Some(window) = app.get_webview_window("main") {
                window.hide().map_err(|e| e.to_string())?;
            }
        }
        CloseAction::Exit => app.exit(0),
        CloseAction::Ask => {}
    }
    Ok(())
}

/// 当前是否已注册开机自启（以操作系统状态为准，不另存配置）。
#[tauri::command]
pub async fn autostart_enabled(app: AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// 开启 / 关闭开机自启。开启后登录时以 `--silent` 静默驻留托盘。
#[tauri::command]
pub async fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(|e| e.to_string())?;
    } else {
        manager.disable().map_err(|e| e.to_string())?;
    }
    manager.is_enabled().map_err(|e| e.to_string())
}

/// 设置是否生成自动提醒。
#[tauri::command]
pub async fn set_notifications_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.notifications_enabled = enabled;
        Ok(())
    })
}

fn notifications_enabled(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .config
        .lock()
        .unwrap()
        .notifications_enabled
}

fn send_notification(app: &AppHandle, kind: NoticeKind, title: &str, body: &str, key: String) {
    if let Err(err) = notifications::publish(app, kind, title, body, Some(key)) {
        eprintln!("保存自动提醒失败：{err}");
    }
}

/// 后台签到失败提醒：同一账号每天最多一条（10 分钟重试不重复轰炸）。
fn notify_checkin_failure(
    app: &AppHandle,
    provider_name: &str,
    account: &Account,
    result: &AccountResult,
    today: &str,
) {
    if result.status != "failed" || !notifications_enabled(app) {
        return;
    }
    let key = format!("fail:{}:{}:{today}", account.provider, account.id);
    send_notification(
        app,
        NoticeKind::Err,
        "签到失败",
        &format!("{provider_name} · {}：{}", account.label, result.message),
        key,
    );
}

/// 领取提醒：给「不代领」的平台（Zcode）用。
///
/// 一旦上游出现可领取的套餐就提醒一次（每天每账号最多一条）。
/// **不写死时间** —— 实测开放时刻并不固定（18:11 / 19:33 / 19:49 / 20:25 都见过），
/// 所以靠轮询 `billing/preview` 判断「现在能不能领」，出现即提醒。
fn notify_claim_reminder(
    app: &AppHandle,
    provider: &dyn Provider,
    account: &Account,
    status: &CheckinStatus,
) {
    if provider.supports_claim() || status.state != ClaimState::Claimable {
        return;
    }
    if !notifications_enabled(app) {
        return;
    }
    let key = format!(
        "claim:{}:{}:{}",
        account.provider,
        account.id,
        scheduler::today()
    );
    send_notification(
        app,
        NoticeKind::Ok,
        "每日额度可领取",
        &format!(
            "{} · {}：{}",
            provider.display_name(),
            account.label,
            status.message
        ),
        key,
    );
}

/// 积分预警：低于阈值每天提醒一次；7 天内到期按到期批次只提醒一次。
fn maybe_notify_quota(
    app: &AppHandle,
    state: &AppState,
    provider_name: &str,
    account: &Account,
    quota: &Quota,
) {
    if !notifications_enabled(app) {
        return;
    }
    let now_ms = chrono::Local::now().timestamp_millis();
    let today = scheduler::today();

    let threshold = state
        .config
        .lock()
        .unwrap()
        .alert_threshold_of(&account.provider);
    if quota.total_remaining < threshold as f64 {
        let key = format!("low:{}:{}:{today}", account.provider, account.id);
        send_notification(
            app,
            NoticeKind::Warn,
            "额度低于预警线",
            &format!(
                "{provider_name} · {}：剩余 {:.2}，低于阈值 {threshold}",
                account.label, quota.total_remaining
            ),
            key,
        );
    }

    if let Some((remaining, earliest)) = quota.expiring_within(7, now_ms) {
        let days = (((earliest - now_ms) as f64) / 86_400_000.0)
            .ceil()
            .max(1.0) as i64;
        let date = chrono::Local
            .timestamp_millis_opt(earliest)
            .single()
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "近期".to_string());
        let key = format!("exp:{}:{}:{earliest}", account.provider, account.id);
        let unit = if account.provider == "zcode" {
            "Token"
        } else {
            "积分"
        };
        send_notification(
            app,
            NoticeKind::Warn,
            "额度即将到期",
            &format!(
                "{provider_name} · {}：{remaining:.2} {unit}将在 {days} 天内到期（{date}）",
                account.label
            ),
            key,
        );
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulePatch {
    enabled: Option<bool>,
    start_minute: Option<u32>,
    end_minute: Option<u32>,
}

/// 在配置锁内应用本次修改，避免连续改动两个时间字段时互相覆盖。
#[tauri::command]
pub async fn set_agent_schedule(
    state: State<'_, AppState>,
    provider_id: String,
    patch: SchedulePatch,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        let mut agent = config.scheduler.agent(&provider_id);
        agent.enabled = patch.enabled.unwrap_or(agent.enabled);
        agent.start_minute = patch.start_minute.unwrap_or(agent.start_minute);
        agent.end_minute = patch.end_minute.unwrap_or(agent.end_minute);
        if !agent.is_valid() {
            return Err("时间窗不合法（起必须早于止）".into());
        }
        config.scheduler.set_agent(&provider_id, agent);
        Ok(())
    })
}

/// 设置某个 agent 的积分预警阈值。
#[tauri::command]
pub async fn set_alert_threshold(
    state: State<'_, AppState>,
    provider_id: String,
    value: u32,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.set_alert_threshold(&provider_id, value);
        Ok(())
    })
}

/// 设置某个 agent 的「同步聊天记录」开关（换号时把本地会话带给目标账号）。
///
/// 只对聊天记录存本地的客户端（WorkBuddy / Qoder）有意义；开关状态落盘
/// config.json，重启后保持。
#[tauri::command]
pub async fn set_chat_sync(
    state: State<'_, AppState>,
    provider_id: String,
    enabled: bool,
) -> Result<AppConfig, String> {
    if !crate::core::chat_sync::supports(&provider_id) {
        return Err(format!(
            "{provider_id} 不支持聊天记录同步（MiniMax 由客户端自动同步）"
        ));
    }
    state.update_config(|config| {
        let mut agent = config.scheduler.agent(&provider_id);
        agent.chat_sync_enabled = enabled;
        config.scheduler.set_agent(&provider_id, agent);
        Ok(())
    })
}

/// 列出换号聊天记录的备份（设置页「历史备份」）。
#[tauri::command]
pub async fn list_chat_backups() -> Result<Vec<crate::core::chat_sync::ChatBackupEntry>, String> {
    Ok(crate::core::chat_sync::list_backups())
}

/// 删除指定的一条备份，返回删除后的最新列表。
#[tauri::command]
pub async fn delete_chat_backup(
    provider: String,
    op_id: String,
) -> Result<Vec<crate::core::chat_sync::ChatBackupEntry>, String> {
    crate::core::chat_sync::delete_backup(&provider, &op_id).map_err(|e| e.to_string())?;
    Ok(crate::core::chat_sync::list_backups())
}

/// 批量清理早于 N 天的备份，返回删除后的最新列表。
#[tauri::command]
pub async fn delete_old_chat_backups(
    days: u32,
) -> Result<Vec<crate::core::chat_sync::ChatBackupEntry>, String> {
    if days == 0 {
        return Err("保留天数至少为 1 天".into());
    }
    crate::core::chat_sync::delete_backups_older_than(days).map_err(|e| e.to_string())?;
    Ok(crate::core::chat_sync::list_backups())
}

/// 列出客户端登录态的多代备份（可回滚）。
#[tauri::command]
pub async fn list_client_login_backups(
    provider: String,
) -> Result<Vec<crate::core::client_backup::ClientLoginBackup>, String> {
    Ok(crate::core::client_backup::list_client_login_backups(&provider))
}

/// 回滚到指定的一代客户端登录态备份，返回回滚后的最新列表。
#[tauri::command]
pub async fn restore_client_login_backup(
    provider: String,
    op_id: String,
) -> Result<Vec<crate::core::client_backup::ClientLoginBackup>, String> {
    crate::core::client_backup::restore_client_login_backup(&provider, &op_id)?;
    Ok(crate::core::client_backup::list_client_login_backups(&provider))
}

/// 裁剪客户端登录态备份：只保留最近 N 代，返回删除后的最新列表。
#[tauri::command]
pub async fn prune_client_login_backups(
    provider: String,
    keep: u32,
) -> Result<Vec<crate::core::client_backup::ClientLoginBackup>, String> {
    crate::core::client_backup::prune_client_login_backups(&provider, keep as usize)?;
    Ok(crate::core::client_backup::list_client_login_backups(&provider))
}

/// 删除指定的一代客户端登录态备份，返回删除后的最新列表。
#[tauri::command]
pub async fn delete_client_login_backup(
    provider: String,
    op_id: String,
) -> Result<Vec<crate::core::client_backup::ClientLoginBackup>, String> {
    crate::core::client_backup::delete_client_login_backup(&provider, &op_id)?;
    Ok(crate::core::client_backup::list_client_login_backups(&provider))
}

/// 切换某个 agent 的自动签到总闸（应急用）。
#[tauri::command]
pub async fn set_scheduler_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.scheduler.enabled = enabled;
        Ok(())
    })
}

/// 切换「自动同步」总开关（积分 / 签到状态 / 账号资料）。
#[tauri::command]
pub async fn set_sync_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.scheduler.sync_enabled = enabled;
        Ok(())
    })
}

/// 切换「错过时间窗自动补签」开关（默认开）。
#[tauri::command]
pub async fn set_catch_up_missed_window(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.scheduler.catch_up_missed_window = enabled;
        Ok(())
    })
}

/// 更新自动更新设置（只改传入字段）。
#[tauri::command]
pub async fn patch_update_config(
    state: State<'_, AppState>,
    patch: crate::core::config::UpdateConfigPatch,
) -> Result<AppConfig, String> {
    state.update_config(|config| {
        config.update.apply_patch(&patch);
        Ok(())
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OldInstallInfo {
    pub display_name: String,
    pub version: String,
    pub install_location: String,
    pub uninstall_string: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallInfo {
    pub version: String,
    pub exe_path: String,
    pub install_dir: String,
    pub has_uninstaller: bool,
    /// `nsis` / `msi` / `portable`
    pub install_kind: String,
    /// 当前 exe 之外的旧安装（用于迁移提示）
    pub old_installs: Vec<OldInstallInfo>,
}

fn normalize_install_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"').trim();
    let trimmed = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
    trimmed
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_lowercase()
}

#[cfg(windows)]
fn read_checkinbox_uninstall_entries() -> Vec<OldInstallInfo> {
    use winreg::enums::{
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };
    use winreg::RegKey;

    let mut out = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let root = RegKey::predef(hive);
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let Ok(uninstall) = root.open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                KEY_READ | view,
            ) else {
                continue;
            };
            for subkey in uninstall.enum_keys().flatten() {
                let Ok(key) = uninstall.open_subkey_with_flags(&subkey, KEY_READ | view) else {
                    continue;
                };
                let display_name: String = key.get_value("DisplayName").unwrap_or_default();
                if !display_name.to_lowercase().contains("checkinbox") {
                    continue;
                }
                let version: String = key.get_value("DisplayVersion").unwrap_or_default();
                let install_location: String = key.get_value("InstallLocation").unwrap_or_default();
                let uninstall_string: String = key.get_value("UninstallString").unwrap_or_default();
                if display_name.trim().is_empty() {
                    continue;
                }
                out.push(OldInstallInfo {
                    display_name,
                    version,
                    install_location,
                    uninstall_string,
                });
            }
        }
    }
    out.sort_by(|left, right| {
        left.display_name
            .cmp(&right.display_name)
            .then(left.install_location.cmp(&right.install_location))
    });
    out.dedup_by(|left, right| {
        left.display_name == right.display_name
            && left.install_location == right.install_location
            && left.uninstall_string == right.uninstall_string
    });
    out
}

#[cfg(not(windows))]
fn read_checkinbox_uninstall_entries() -> Vec<OldInstallInfo> {
    Vec::new()
}

/// 当前 exe 的安装形态与旧安装信息，供更新 UI 判断能否自动安装。
#[tauri::command]
pub async fn get_install_info() -> Result<InstallInfo, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe
        .parent()
        .ok_or_else(|| "无法确定 exe 目录".to_string())?
        .to_path_buf();
    let current = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
    let current_key = normalize_install_path(&current.to_string_lossy());
    let has_uninstaller = std::fs::read_dir(&dir)
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case("uninstall.exe")
            })
        })
        .unwrap_or(false);

    let entries = read_checkinbox_uninstall_entries();
    let current_entry = entries
        .iter()
        .find(|entry| {
            !entry.install_location.trim().is_empty()
                && normalize_install_path(&entry.install_location) == current_key
        });
    let install_kind = match current_entry {
        Some(entry)
            if entry
                .uninstall_string
                .to_lowercase()
                .contains("msiexec") =>
        {
            "msi"
        }
        Some(_) => "nsis",
        None if has_uninstaller => "nsis",
        None => "portable",
    };
    let old_installs = entries
        .into_iter()
        .filter(|entry| {
            !entry.install_location.trim().is_empty()
                && normalize_install_path(&entry.install_location) != current_key
        })
        .collect();

    Ok(InstallInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        exe_path: exe.to_string_lossy().to_string(),
        install_dir: dir.to_string_lossy().to_string(),
        has_uninstaller,
        install_kind: install_kind.to_string(),
        old_installs,
    })
}

/// 设置某个 agent 的数据自动同步间隔（分钟）。
#[tauri::command]
pub async fn set_refresh_interval(
    state: State<'_, AppState>,
    provider_id: String,
    minutes: u32,
) -> Result<AppConfig, String> {
    if !(1..=24 * 60).contains(&minutes) {
        return Err("同步间隔需在 1–1440 分钟之间".into());
    }
    state.update_config(|config| {
        let mut agent = config.scheduler.agent(&provider_id);
        agent.refresh_interval_minutes = minutes;
        config.scheduler.set_agent(&provider_id, agent);
        Ok(())
    })
}

/// 设置界面自动刷新间隔（秒）。0 = 关闭前台轮询（仅手动刷新 / 后台同步事件更新）。
#[tauri::command]
pub async fn set_ui_refresh_interval(
    state: State<'_, AppState>,
    seconds: u32,
) -> Result<AppConfig, String> {
    if seconds != 0 && !(10..=3600).contains(&seconds) {
        return Err("界面刷新间隔需为 0（关闭）或 10–3600 秒".into());
    }
    state.update_config(|config| {
        config.ui_refresh_seconds = seconds;
        Ok(())
    })
}

/// 实时核对 WorkBuddy 当前免费模型（模型目录与客户端对话选择器同源）。
#[tauri::command]
pub async fn fetch_workbuddy_free_models(
    state: State<'_, AppState>,
    account_id: Option<String>,
) -> Result<Vec<crate::providers::workbuddy::FreeModel>, String> {
    let store = state.store.lock().unwrap().clone();
    let accounts = store.list_of("workbuddy");
    let account = match account_id {
        Some(id) => accounts.into_iter().find(|a| a.id == id),
        None => accounts.into_iter().next(),
    }
    .ok_or_else(|| "暂无 WorkBuddy 账号，先导入或添加账号".to_string())?;
    let cred = store
        .credential("workbuddy", &account.id)
        .map_err(|e| e.to_string())?;
    crate::providers::workbuddy::fetch_free_models(&cred)
        .await
        .map_err(|e| e.to_string())
}

/// 改某个平台的显示开关（侧栏导航 / 首页卡片）。
/// 隐藏只影响显示，自动签到与后台同步不受影响；None = 该字段不改。
#[tauri::command]
pub async fn set_agent_visibility(
    state: State<'_, AppState>,
    provider_id: String,
    sidebar: Option<bool>,
    home: Option<bool>,
    launch: Option<bool>,
) -> Result<AppConfig, String> {
    if sidebar.is_none() && home.is_none() && launch.is_none() {
        return Err("没有要修改的显示开关".into());
    }
    state.update_config(|config| {
        let mut vis = config.visibility_of(&provider_id);
        if let Some(v) = sidebar {
            vis.sidebar = v;
        }
        if let Some(v) = home {
            vis.home = v;
        }
        if let Some(v) = launch {
            vis.launch = v;
        }
        config.agent_visibility.insert(provider_id, vis);
        Ok(())
    })
}

/// 立即同步全部账号（不等间隔）。
#[tauri::command]
pub async fn sync_now(app: AppHandle, state: State<'_, AppState>) -> Result<TaskSummary, String> {
    sync_now_inner(&app, &state).await
}

pub async fn sync_now_inner(app: &AppHandle, state: &AppState) -> Result<TaskSummary, String> {
    let _running = state
        .sync_running
        .try_lock()
        .map_err(|_| "正在同步，请稍后再试")?;
    let accounts = state.store.lock().unwrap().list();
    if accounts.is_empty() {
        return Ok(TaskSummary {
            kind: NoticeKind::Warn,
            message: "暂无可同步的账号。".into(),
        });
    }
    let mut done = 0usize;
    for account in &accounts {
        if sync_one(app, state, account).await {
            done += 1;
        }
    }
    let now = chrono::Local::now().timestamp();
    {
        let mut sched = state.scheduler.lock().unwrap();
        for provider in state.providers.iter() {
            if accounts.iter().any(|a| a.provider == provider.id()) {
                sched.mark_synced(provider.id(), now);
            }
        }
        let _ = sched.save();
    }
    let _ = app.emit("accounts-changed", ());
    let incomplete = accounts.len() - done;
    Ok(if incomplete == 0 {
        TaskSummary {
            kind: NoticeKind::Ok,
            message: format!("已同步 {done} 个账号。"),
        }
    } else {
        TaskSummary {
            kind: NoticeKind::Warn,
            message: format!("已同步 {done} 个账号，{incomplete} 个未能完整同步。"),
        }
    })
}

/// 在文件管理器里打开应用数据目录。
#[tauri::command]
pub async fn open_data_dir() -> Result<(), String> {
    let dir = crate::core::paths::data_dir();
    crate::core::paths::ensure_dir(&dir).map_err(|e| e.to_string())?;
    open::that(dir).map_err(|e| e.to_string())
}

/// 把某个账号设为该 agent 的当前账号（多账号切换）。
#[tauri::command]
pub async fn set_active_account(
    state: State<'_, AppState>,
    provider_id: String,
    account_id: String,
) -> Result<AppConfig, String> {
    let store = state.store.lock().unwrap().clone();
    if !store.contains(&provider_id, &account_id) {
        return Err(format!("账号不存在：{account_id}"));
    }
    state.update_config(|config| {
        config.set_active(&provider_id, &account_id);
        Ok(())
    })
}

/// 打开该 agent 的客户端（用当前账号的上下文）。
#[tauri::command]
pub async fn launch_client(provider_id: String) -> Result<String, String> {
    let exe = crate::core::launcher::launch(&provider_id).map_err(|e| e.to_string())?;
    Ok(exe.to_string_lossy().to_string())
}

/// 读客户端当前实际登录的账号（只读，不改任何文件）。
#[tauri::command]
pub async fn detect_client_account(
    provider_id: String,
) -> Result<Option<crate::core::client_switch::DetectedAccount>, String> {
    crate::core::client_switch::detect(&provider_id).map_err(|e| e.to_string())
}

/// 旧版浏览器导入可能以 token 指纹作池内 ID。用真实 UID 找回原记录，保留签到和趋势历史。
fn workbuddy_pool_account(store: &AccountStore, uid: &str) -> Option<Account> {
    let accounts = store.list_of("workbuddy");
    accounts
        .iter()
        .find(|account| account.id == uid)
        .cloned()
        .or_else(|| {
            accounts.into_iter().find(|account| {
                store
                    .credential("workbuddy", &account.id)
                    .ok()
                    .and_then(|cred| workbuddy::credential_uid(&cred))
                    .as_deref() == Some(uid)
            })
        })
}

fn reuse_workbuddy_pool_id(store: &AccountStore, account: &mut Account) {
    if let Some(existing) = workbuddy_pool_account(store, &account.id) {
        account.id = existing.id;
        account.created_at = existing.created_at;
        account.last_used = existing.last_used;
    }
}

/// 旧版 Qoder 对空 UID 生成了一个固定的池内 ID。身份恢复后继续使用旧记录的历史。
fn qoder_legacy_pool_id(store: &AccountStore, canonical: &str) -> Option<String> {
    if store.contains("qoder", canonical) {
        return None;
    }
    let legacy = qoder::account_id("");
    let cred = store.credential("qoder", &legacy).ok()?;
    let uid = qoder::user_id_of(&cred)?;
    (qoder::account_id(uid) == canonical).then_some(legacy)
}

fn reuse_qoder_pool_id(store: &AccountStore, account: &mut Account) {
    if let Some(legacy) = qoder_legacy_pool_id(store, &account.id) {
        if let Some(existing) = store.accounts.get(&AccountStore::key("qoder", &legacy)) {
            account.created_at = existing.account.created_at;
            account.last_used = existing.account.last_used;
        }
        account.id = legacy;
    }
}

/// 把客户端**当前登录**的账号捕获进账号池（借鉴 Cockpit 的切换保护）。
///
/// 「切换客户端账号」切走前调用：客户端同一时刻只能登一个号，切走后它的
/// 凭据就不再更新 —— 先捕获，谁都不丢，且池里留的是客户端续期过的最新凭据。
/// MiniMax / 妙手走 `discover`（读明文登录态）；Qoder 解密 auth.v1.dat；
/// WorkBuddy 走 `workbuddy_client_login`（新版解密共享 auth 文件、老版解密
/// state.vscdb —— `discover` 优先读 Cockpit 账号库，可能不含客户端现场登录的
/// 账号，所以这里单独捕获）。
async fn capture_client_login(state: &AppState, provider_id: &str) {
    if provider_id == "qoder" {
        if let Some((mut account, cred)) = crate::core::client_switch::qoder_client_login() {
            let mut store = state.store.lock().unwrap();
            reuse_qoder_pool_id(&store, &mut account);
            if let Ok(previous) = store.credential("qoder", &account.id) {
                if qoder::validate_switch_credential(&cred).is_err()
                    || cred_expiry_ms(&previous) > cred_expiry_ms(&cred)
                {
                    return;
                }
            }
            let _ = store.upsert(account, &cred);
        }
        return;
    }
    if provider_id == "workbuddy" {
        if let Some((mut account, cred)) = crate::core::client_switch::workbuddy_client_login() {
            let mut store = state.store.lock().unwrap();
            reuse_workbuddy_pool_id(&store, &mut account);
            let _ = store.upsert(account, &cred);
        }
        return;
    }
    if provider_id == "trae" {
        if let Some((account, mut cred)) = crate::providers::trae::read_local_account() {
            let mut store = state.store.lock().unwrap();
            let existing = store.credential("trae", &account.id).ok();
            let keep = existing
                .as_ref()
                .and_then(|old| old["checkin_device_id"].as_str())
                .filter(|id| crate::providers::trae::is_valid_device_id(id));
            if let Some(id) = keep {
                cred["checkin_device_id"] = serde_json::json!(id);
                cred["device_source"] = existing
                    .as_ref()
                    .and_then(|old| old.get("device_source"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
            } else {
                let used: Vec<String> = store
                    .list_of("trae")
                    .into_iter()
                    .filter_map(|item| {
                        store
                            .credential("trae", &item.id)
                            .ok()
                            .and_then(|old| {
                                old["checkin_device_id"].as_str().map(str::to_string)
                            })
                    })
                    .collect();
                let real = cred["login_device_id"].as_str().unwrap_or("");
                let prefer_real = !used.iter().any(|id| id == real);
                let id = crate::providers::trae::assign_checkin_device_id(
                    &account.id,
                    real,
                    &used,
                    prefer_real,
                );
                cred["checkin_device_id"] = serde_json::json!(id);
            }
            let _ = store.upsert(account, &cred);
        }
        return;
    }
    let Some(provider) = state.provider(provider_id) else {
        return;
    };
    let Ok(found) = provider.discover().await else {
        return;
    };
    let mut store = state.store.lock().unwrap();
    for (account, cred) in found {
        if provider_id == "minimax" {
            if let Ok(previous) = store.credential("minimax", &account.id) {
                if minimax::switch_tokens(&cred).is_err()
                    || cred_expiry_ms(&previous) > cred_expiry_ms(&cred)
                {
                    continue;
                }
            }
        }
        let _ = store.upsert(account, &cred);
    }
}

/// 把客户端切换成指定账号，然后启动客户端。
///
/// ⚠️ 会改写客户端的登录态文件（先备份）。**客户端在运行时会被拒绝**
/// （`client_switch::switch` 入口统一拦截），否则它内存里的旧登录态
/// 会覆盖我们写进去的文件。
///
/// 切换成功后顺手把这个账号设为该 agent 的「当前账号」——
/// 客户端登的是谁，工具里的当前账号就应该是谁，两边保持一致。
#[tauri::command]
pub async fn switch_client_account(
    app: AppHandle,
    state: State<'_, AppState>,
    provider_id: String,
    account_id: String,
) -> Result<crate::core::client_switch::SwitchOutcome, String> {
    if !crate::core::client_switch::is_switchable(&provider_id) {
        return Err(format!(
            "{provider_id} 不支持切换客户端账号（凭据格式无法注入）"
        ));
    }
    let store = state.store.lock().unwrap().clone();
    let account = store
        .list_of(&provider_id)
        .into_iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("账号不存在：{account_id}"))?;
    let cred = store
        .credential(&provider_id, &account_id)
        .map_err(|e| e.to_string())?;
    let cred = prepare_switch_cred(&state, &account, cred).await?;

    let mut report_progress = |stage: &str| {
        let _ = app.emit(
            "switch-progress",
            SwitchProgressEvent {
                provider_id: provider_id.clone(),
                account_id: account_id.clone(),
                account_label: account.label.clone(),
                stage: stage.to_string(),
            },
        );
    };

    // 第一步：关客户端。捕获放在关**之后** —— 客户端退出前最后一次提交的凭据
    // 最活（它自己会按点刷新并轮换 RT，先捕获可能拿到下一分钟就作废的 RT）
    report_progress("closing");
    let was_running = crate::core::launcher::is_running(&provider_id);
    crate::core::client_switch::begin_switch(&provider_id).map_err(|e| e.to_string())?;

    // 第二步：捕获客户端当前登录的账号 —— 谁都不丢，且是客户端最后提交的凭据
    report_progress("capturing");
    capture_client_login(&state, &provider_id).await;

    // 第三步：切换前保活 —— 写进客户端的必须是「活」凭据。MiniMax 客户端遇到
    // 死 RT 会**删掉凭据**退回登录页（用户只能重新录入），所以过期必须刷新
    // 成功才写，刷不动就如实报错
    report_progress("validating");
    let cred = match switch_cred_guard(&state, &account, cred).await {
        Ok(cred) => cred,
        Err(e) => {
            if was_running {
                let _ = crate::core::launcher::launch(&provider_id);
            }
            return Err(e);
        }
    };

    // 「同步聊天记录」开关：开着且平台支持时，换号会把本地会话记录带给目标账号
    let chat_sync_enabled = {
        let config = state.config.lock().unwrap();
        config.scheduler.agent(&provider_id).chat_sync_enabled
    };

    let outcome = crate::core::client_switch::finish_switch(
        &provider_id,
        &cred,
        &account_id,
        &account.label,
        chat_sync_enabled,
        &mut report_progress,
    )
    .map_err(|e| e.to_string())?;

    // 客户端已经登录这个账号了，工具里的「当前账号」跟着同步
    state.update_config(|config| {
        config.set_active(&provider_id, &account_id);
        Ok(())
    })?;
    Ok(outcome)
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SwitchProgressEvent {
    provider_id: String,
    account_id: String,
    account_label: String,
    stage: String,
}

/// 客户端是否正在运行（前端在「切换客户端账号」前先问一次，给个友好的拦截提示）。
#[tauri::command]
pub async fn client_running(provider_id: String) -> Result<bool, String> {
    Ok(crate::core::launcher::is_running(&provider_id))
}

/// 读取最近若干天的签到流水。
#[tauri::command]
pub async fn get_logs(days: Option<i64>) -> Result<Vec<LogEntry>, String> {
    logging::recent(days.unwrap_or(7)).map_err(|e| e.to_string())
}

/// 在系统默认浏览器里打开链接（Qoder 授权页等）。
#[tauri::command]
pub async fn open_external(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("只允许打开 http(s) 链接".into());
    }
    open::that(url).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// 内部
// ---------------------------------------------------------------------------

/// 让账号凭据保持新鲜 —— **多账号状态保存的核心**（方案借鉴 Cockpit Tools）：
///
/// * 客户端**当前登录**的账号 → 从客户端登录态**捕获**最新 token 回写池
///   （客户端开着会自动续期；捕获不动客户端的 refresh token，现场安全）。
/// * **不在客户端里**的账号 → token 临过期时用 refresh token 走 OAuth 刷新。
///   MiniMax 的 RT 每次刷新都会轮换，新 RT 回写池 —— 所以池里的账号即使
///   长期不是当前登录，也能一直活着、正常签到。
///
/// MiniMax 的 RT「用一次就作废」，所以这里有三道防线（对齐官方 MiniMax CLI 的
/// single-flight 与 Cockpit Tools 的 `prepare_account_tokens_before_exchange`）：
///   1. **按账号加锁**：同一账号同时只有一个刷新在跑，不同账号互不阻塞；
///   2. **拿到锁后重读账号池**：别的任务可能刚刷新过，直接采纳它的新 RT，
///      不拿旧 RT 去撞 `invalid_grant`；
///   3. **先落盘再解锁**：后面的调用方重读到的就是新 RT，不会踩空。
///
/// 刷新失败（RT 被吊销等）返回原凭据，调用方按普通错误如实展示。
async fn ensure_fresh_cred(
    state: &AppState,
    account: &Account,
    cred: &serde_json::Value,
) -> serde_json::Value {
    if account.provider == "qoder" {
        return ensure_fresh_qoder(state, account, cred).await;
    }
    if account.provider == "trae" {
        return ensure_fresh_trae(state, account, cred).await;
    }
    if account.provider != "minimax" {
        // 其他平台的 token 有效期是「天」级，池里的快照直接够用
        return cred.clone();
    }

    let lock = refresh_lock_for(account).await;
    let _guard = lock.lock().await;

    // 重读账号池：可能刚被别的任务刷新过（它的落盘在释放锁之前完成）
    let latest = state
        .store
        .lock()
        .unwrap()
        .credential(&account.provider, &account.id)
        .unwrap_or_else(|_| cred.clone());
    if latest != *cred {
        // 已经有人更新过了（刷新或客户端捕获），直接采纳
        return latest;
    }

    // 当前登录：捕获客户端里的最新凭据（不动它的 RT，避免把在线登录顶掉）
    let login = crate::providers::minimax::client_login_state(account).await;
    if let crate::providers::minimax::ClientLoginState::Same(fresh) = &login {
        if *fresh != latest {
            persist_cred(state, account, fresh);
        }
        return fresh.clone();
    }

    // 客户端在运行但身份无法确认（探测失败等）：宁可不刷新，也不能轮换掉
    // 客户端手里的 RT —— 那会让客户端下一次刷新直接 invalid_grant 掉登录。
    // 进程状态是三态：枚举失败 = 「不知道」，不等于「没在跑」，同样不刷。
    let process = crate::core::launcher::client_process_state("minimax");
    if !login.allow_self_refresh(process) {
        return latest;
    }

    // 非当前登录：还有 5 分钟以上有效期就不动，临过期才刷新
    if !needs_refresh(&latest, chrono::Utc::now().timestamp_millis()) {
        return latest;
    }

    let provider = crate::providers::minimax::MiniMaxProvider::new();
    match provider.refresh(account, &latest).await {
        Ok(Some(fresh)) => {
            persist_cred(state, account, &fresh);
            fresh
        }
        // 刷新失败（RT 吊销等）返回原凭据，调用方按普通错误如实展示
        _ => latest,
    }
}

/// 临过期（剩余不足 5 分钟）才需要刷新；缺 `expires_at_ms` 字段时一律刷新。
fn needs_refresh(cred: &serde_json::Value, now_ms: i64) -> bool {
    let expires = cred
        .get("expires_at_ms")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    expires <= now_ms + 5 * 60_000
}

/// 凭据到期时间（毫秒）：MiniMax 用 `expires_at_ms`，Qoder 用 `expires_at`。
fn cred_expiry_ms(cred: &serde_json::Value) -> i64 {
    cred.get("expires_at_ms")
        .and_then(|v| v.as_i64())
        .or_else(|| cred.get("expires_at").and_then(|v| v.as_i64()))
        .unwrap_or(0)
}

/// Qoder：剩余不足 5 分钟才续期；没有到期时间视为未知，不主动续期
/// （避免每轮同步都去换一次 refresh token）。
fn qoder_needs_refresh(cred: &serde_json::Value, now_ms: i64) -> bool {
    let expires = cred_expiry_ms(cred);
    expires > 0 && expires <= now_ms + 5 * 60_000
}

/// Qoder 凭据续期：access token 临期时用 refresh token 换新并回写账号池。
///
/// 客户端当前登录的正是这个账号时，优先采纳 `auth.v1.dat` 里客户端自己
/// 续期过的凭据；否则走 `POST /api/v1/deviceToken/refresh`。服务端会轮换
/// refresh token，但旧值不会立即失效，所以不会把桌面客户端顶下线。
async fn ensure_fresh_qoder(
    state: &AppState,
    account: &Account,
    cred: &serde_json::Value,
) -> serde_json::Value {
    let lock = refresh_lock_for(account).await;
    let _guard = lock.lock().await;

    let latest = state
        .store
        .lock()
        .unwrap()
        .credential(&account.provider, &account.id)
        .unwrap_or_else(|_| cred.clone());
    if latest != *cred {
        return latest;
    }

    if !qoder_needs_refresh(&latest, chrono::Utc::now().timestamp_millis()) {
        return latest;
    }

    // 客户端当前登录的就是这个账号：它文件里的凭据可能刚续期过，优先采纳
    if let Some((_, fresh)) = crate::core::client_switch::qoder_client_login() {
        if qoder::user_id_of(&fresh) == qoder::user_id_of(&latest)
            && qoder::validate_switch_credential(&fresh).is_ok()
            && cred_expiry_ms(&fresh) > cred_expiry_ms(&latest)
        {
            persist_cred(state, account, &fresh);
            return fresh;
        }
    }

    let Some(provider) = state.provider("qoder") else {
        return latest;
    };
    match provider.refresh(account, &latest).await {
        Ok(Some(fresh)) => {
            persist_cred(state, account, &fresh);
            fresh
        }
        // 续期失败（RT 已过期等）返回原凭据，调用方按普通错误如实展示
        _ => latest,
    }
}

/// Trae 凭据保鲜。
///
/// 和 MiniMax 同一套护栏：当前登录账号在客户端运行时**绝不自行刷新**
/// （RT 轮换可能把客户端顶掉），只采纳客户端文件里的新 token；客户端确认
/// 没在跑时才刷新并回写 storage.json。非当前账号可以自刷。
async fn ensure_fresh_trae(
    state: &AppState,
    account: &Account,
    cred: &serde_json::Value,
) -> serde_json::Value {
    let lock = refresh_lock_for(account).await;
    let _guard = lock.lock().await;

    let latest = state
        .store
        .lock()
        .unwrap()
        .credential(&account.provider, &account.id)
        .unwrap_or_else(|_| cred.clone());
    if latest != *cred {
        return latest;
    }
    if !trae_needs_refresh(&latest, chrono::Utc::now().timestamp_millis()) {
        return latest;
    }

    let login = crate::providers::trae::client_login_state(account, &latest);
    let process = crate::core::launcher::client_process_state("trae");

    match login {
        crate::providers::trae::ClientLoginState::Same(fresh) => {
            // 客户端在跑 / 状态不明：只采纳文件里的新凭据，不自行刷新。
            if process != crate::core::launcher::ClientProcessState::Absent {
                if cred_expiry_ms(&fresh) > cred_expiry_ms(&latest) {
                    persist_cred(state, account, &fresh);
                    return fresh;
                }
                return latest;
            }
            // 客户端确认不在：可以安全刷新并回写。
            let Some(provider) = state.provider("trae") else {
                return latest;
            };
            match provider.refresh(account, &latest).await {
                Ok(Some(fresh)) => {
                    persist_cred(state, account, &fresh);
                    if let Err(e) =
                        crate::providers::trae::TraeProvider::write_back_local_auth(&fresh)
                    {
                        eprintln!("Trae 刷新后回写 storage.json 失败（凭据已保存在账号池）：{e}");
                    }
                    fresh
                }
                Ok(None) => latest,
                Err(e) => {
                    eprintln!("Trae 刷新失败：{e}");
                    latest
                }
            }
        }
        crate::providers::trae::ClientLoginState::Other => {
            let Some(provider) = state.provider("trae") else {
                return latest;
            };
            match provider.refresh(account, &latest).await {
                Ok(Some(fresh)) => {
                    persist_cred(state, account, &fresh);
                    fresh
                }
                _ => latest,
            }
        }
        crate::providers::trae::ClientLoginState::Unknown => {
            // 身份不明时宁可不动。OAuth 账号不在客户端里，确认客户端没跑才允许自刷。
            if process == crate::core::launcher::ClientProcessState::Absent
                && latest["cred_source"].as_str() == Some("oauth")
            {
                let Some(provider) = state.provider("trae") else {
                    return latest;
                };
                if let Ok(Some(fresh)) = provider.refresh(account, &latest).await {
                    persist_cred(state, account, &fresh);
                    return fresh;
                }
            }
            latest
        }
    }
}

fn trae_needs_refresh(cred: &serde_json::Value, now_ms: i64) -> bool {
    let expires = cred["expires_at_ms"].as_i64().unwrap_or(0);
    // 到期时间未知（0）时不主动刷，避免每轮都换 RT。
    expires > 0 && expires <= now_ms + 2 * 60 * 60 * 1000
}

fn persist_cred(state: &AppState, account: &Account, cred: &serde_json::Value) {
    let mut store = state.store.lock().unwrap();
    let _ = store.upsert(account.clone(), cred);
}

/// 在关闭客户端前校验目标凭据。只从已经验证为同一账号的来源恢复缺失字段。
async fn prepare_switch_cred(
    state: &AppState,
    account: &Account,
    cred: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let repaired = match account.provider.as_str() {
        "workbuddy" if cred["uid"].as_str().map(str::trim).map_or(true, str::is_empty) => state
            .workbuddy
            .recover_switch_identity(&cred)
            .await
            .ok_or_else(|| {
                format!(
                    "无法从账号「{}」的 WorkBuddy 授权恢复 uid，请重新通过浏览器授权该账号后再切换",
                    account.label
                )
            })?,
        "qoder" => {
            let mut repaired = cred.clone();
            if qoder::user_id_of(&repaired).is_none() {
                let uid = state.qoder.resolve_user_id(&cred).await.map_err(|e| e.to_string())?;
                repaired["user_id"] = serde_json::json!(uid);
            }
            if qoder::validate_switch_credential(&repaired).is_err() {
                if let Some((_, local)) = crate::core::client_switch::qoder_client_login() {
                    if qoder::user_id_of(&local) == qoder::user_id_of(&repaired) {
                        repaired = local;
                    }
                }
            }
            qoder::validate_switch_credential(&repaired).map_err(|e| e.to_string())?;
            crate::core::client_switch::qoder_switch_dir().map_err(|e| e.to_string())?;
            repaired
        }
        "minimax" => {
            let repaired = if minimax::switch_tokens(&cred).is_ok() {
                cred.clone()
            } else {
                match minimax::client_login_state(account).await {
                    minimax::ClientLoginState::Same(local) => local,
                    _ => cred.clone(),
                }
            };
            minimax::switch_tokens(&repaired).map_err(|e| e.to_string())?;
            crate::core::client_switch::minimax_switch_path(&repaired).map_err(|e| e.to_string())?;
            repaired
        }
        "trae" => {
            let mut repaired = cred.clone();
            if trae::validate_switch_credential(&repaired).is_err() {
                if let trae::ClientLoginState::Same(local) = trae::client_login_state(account, &cred) {
                    repaired = local;
                }
            }
            trae::preflight_switch(&repaired).map_err(|e| e.to_string())?;
            repaired
        }
        _ => return Ok(cred),
    };
    if repaired == cred {
        return Ok(cred);
    }
    let mut store = state.store.lock().unwrap();
    let latest = store
        .credential(&account.provider, &account.id)
        .map_err(|e| e.to_string())?;
    if latest != cred {
        return Err("目标账号凭据在校验期间已更新，请重试切换".into());
    }
    store
        .upsert(account.clone(), &repaired)
        .map_err(|e| e.to_string())?;
    Ok(repaired)
}

/// 切换前的凭据保活（目前只对 MiniMax 严格）：写进客户端的必须是「活」凭据。
///
/// MiniMax 客户端在 refresh token 失效时会**删掉凭据**退回登录页
/// （2026-11-05 实测：切换写入了已过期、RT 已被客户端自己轮换的凭据 →
/// 客户端启动刷新 `invalid_grant` → `delete_credentials` → 用户被迫重新录入）。
/// 所以切换路径比其它路径更严格：
///   * 客户端当前登录的就是这个账号 → 直接用它文件里的最新凭据（最活）；
///   * 凭据临期/已过期 → **强制刷新成功才写**；刷新失败 = RT 已死 → 拒绝切换，
///     绝不把死凭据写进去（写死凭据的代价是用户重新走授权，代价比「这次不切」大得多）。
///
/// 调用时机在 `begin_switch`（客户端已关闭）之后：此时刷新轮换 RT 没有
/// 「把在线登录顶掉」的风险。
async fn switch_cred_guard(
    state: &AppState,
    account: &Account,
    cred: serde_json::Value,
) -> Result<serde_json::Value, String> {
    if account.provider == "qoder" {
        let lock = refresh_lock_for(account).await;
        let _guard = lock.lock().await;
        let current = state
            .store
            .lock()
            .unwrap()
            .credential("qoder", &account.id)
            .map_err(|e| e.to_string())?;
        qoder::validate_switch_credential(&current).map_err(|e| e.to_string())?;
        if cred_expiry_ms(&current) > chrono::Utc::now().timestamp_millis() {
            return Ok(current);
        }
        let fresh = state
            .qoder
            .refresh(account, &current)
            .await
            .map_err(|e| e.to_string())?
            .filter(|fresh| cred_expiry_ms(fresh) > chrono::Utc::now().timestamp_millis())
            .ok_or_else(|| "无法确认 Qoder CN 凭据有效期，请重新通过浏览器授权该账号".to_string())?;
        qoder::validate_switch_credential(&fresh).map_err(|e| e.to_string())?;
        persist_cred(state, account, &fresh);
        return Ok(fresh);
    }
    if account.provider == "workbuddy" {
        return state
            .store
            .lock()
            .unwrap()
            .credential(&account.provider, &account.id)
            .map_err(|e| e.to_string());
    }
    if account.provider == "trae" {
        // 换号时客户端已经关闭。先校验目标账号的登录态：客户端手动换号会
        // 作废旧账号的会话，写死凭据会让客户端启动后直接清登录态。
        let provider = crate::providers::trae::TraeProvider::new();
        let mut cred = state
            .store
            .lock()
            .unwrap()
            .credential("trae", &account.id)
            .map_err(|e| e.to_string())?;
        trae::validate_switch_credential(&cred).map_err(|e| e.to_string())?;
        if trae_needs_refresh(&cred, chrono::Utc::now().timestamp_millis()) {
            cred = match provider.refresh(account, &cred).await {
                Ok(Some(fresh)) => {
                    persist_cred(state, account, &fresh);
                    fresh
                }
                _ => {
                    return Err(format!(
                        "账号「{}」的 Trae 凭据已失效（refresh token 被轮换或已过期）：请重新导入该账号后再切换",
                        account.label
                    ))
                }
            };
        }
        if matches!(provider.check_login(&cred).await, Ok(true)) {
            return Ok(cred);
        }
        // 会话可能被客户端换号作废：强制刷新一次再校验。
        if let Ok(Some(fresh)) = provider.refresh(account, &cred).await {
            if matches!(provider.check_login(&fresh).await, Ok(true)) {
                persist_cred(state, account, &fresh);
                return Ok(fresh);
            }
        }
        return Err(format!(
            "账号「{}」的 Trae 登录态已失效（可能已被客户端换号作废）：请先在 Trae 客户端登录该账号并重新导入，或完成浏览器授权后再切换",
            account.label
        ));
    }
    if account.provider != "minimax" {
        // 其他平台 token 是「天」级有效期，池里的快照直接够用
        return Ok(cred);
    }

    let lock = refresh_lock_for(account).await;
    let _guard = lock.lock().await;
    let cred = state
        .store
        .lock()
        .unwrap()
        .credential("minimax", &account.id)
        .map_err(|e| e.to_string())?;
    // 客户端当前登录的就是这个账号：用它文件里的最新凭据（顺手落盘）
    let cred = match crate::providers::minimax::client_login_state(account).await {
        crate::providers::minimax::ClientLoginState::Same(fresh)
            if minimax::switch_tokens(&fresh).is_ok()
                && cred_expiry_ms(&fresh) >= cred_expiry_ms(&cred) =>
        {
            if fresh != cred {
                persist_cred(state, account, &fresh);
            }
            fresh
        }
        _ => cred,
    };
    minimax::switch_tokens(&cred).map_err(|e| e.to_string())?;

    if !needs_refresh(&cred, chrono::Utc::now().timestamp_millis()) {
        return Ok(cred);
    }

    // 临期/已过期：强制刷新一次。失败 = RT 被轮换或吊销 → 拒写
    let provider = crate::providers::minimax::MiniMaxProvider::new();
    match provider.refresh(account, &cred).await {
        Ok(Some(fresh)) => {
            persist_cred(state, account, &fresh);
            Ok(fresh)
        }
        _ => Err(format!(
            "账号「{}」的凭据已失效（refresh token 被轮换或已过期）：请重新导入该账号后再切换",
            account.label
        )),
    }
}

/// 按账号的刷新锁：MiniMax 的 RT 用一次就作废，并发刷新会让其中一个必然失败
/// （服务端可能因此吊销整个 token family）。同一账号串行、不同账号并行。
static REFRESH_LOCKS: std::sync::OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
> = std::sync::OnceLock::new();

async fn refresh_lock_for(account: &Account) -> Arc<tokio::sync::Mutex<()>> {
    let map = REFRESH_LOCKS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    map.lock()
        .await
        .entry(account.id.clone())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// 核心签到流程：查状态 → 需要则领取。
///
/// **只返回结果，不落流水** —— 落不落流水由调用方决定（调度器对
/// 「上游还没开窗」的重试不落，否则一个时间窗内会刷出几十条没信息量的记录）。
async fn run_checkin(
    provider: &dyn Provider,
    account: &Account,
    cred: &serde_json::Value,
) -> AccountResult {
    let status = match provider.status(account, cred).await {
        Ok(s) => s,
        Err(e) => {
            return AccountResult {
                account_id: account.id.clone(),
                provider: account.provider.clone(),
                label: account.label.clone(),
                status: "failed".into(),
                points: 0,
                message: e.to_string(),
            };
        }
    };

    // 只展示 + 提醒的平台（Zcode）不代领：领取要过官方客户端的阿里云验证码，
    // 第三方做不了。直接按原状态返回，不碰 claim()。
    if !provider.supports_claim() {
        return AccountResult {
            account_id: account.id.clone(),
            provider: account.provider.clone(),
            label: account.label.clone(),
            status: "skipped".into(),
            points: status.points,
            message: status.message,
        };
    }

    if status.state != ClaimState::Claimable {
        return AccountResult {
            account_id: account.id.clone(),
            provider: account.provider.clone(),
            label: account.label.clone(),
            status: if status.state == ClaimState::Claimed {
                "already".into()
            } else {
                "skipped".into()
            },
            points: status.points,
            message: if status.message.is_empty() {
                "今日无签到活动".into()
            } else {
                status.message.clone()
            },
        };
    }

    let outcome = match provider.claim(account, cred).await {
        Ok(o) => o,
        Err(e) => {
            return AccountResult {
                account_id: account.id.clone(),
                provider: account.provider.clone(),
                label: account.label.clone(),
                status: "failed".into(),
                points: 0,
                message: e.to_string(),
            };
        }
    };

    AccountResult {
        account_id: account.id.clone(),
        provider: account.provider.clone(),
        label: account.label.clone(),
        status: if outcome.state == ClaimState::Claimed {
            "success".into()
        } else {
            "failed".into()
        },
        points: outcome.points,
        message: outcome.message.clone(),
    }
}

/// 落一条签到流水。
///
/// 落流水规则（2026-10-26 按需求调整，10-27 补失败节流）：
/// * `success` —— 当天每账号只保留一条（`logging::has_success_today` 去重）；
/// * `failed` —— 可重复，但 10 分钟节流：调度器在窗内每 ~30 秒重试一次
///   失败账号，不节流的话一个死账号一小时能刷出 240 条相同失败；
/// * `already` / `skipped` —— 不落：「今日已签」没有信息量只会刷屏，
///   「未开窗跳过」会在时间窗内反复出现。
fn record_result(account: &Account, result: &AccountResult) -> bool {
    let recorded = should_record_status(
        &result.status,
        result.status == "success" && logging::has_success_today(&account.provider, &account.id),
        result.status == "failed"
            && logging::has_recent_failure(&account.provider, &account.id, 10),
    );
    if recorded {
        if let Err(err) = logging::append(&LogEntry::new(
            &account.provider,
            &account.id,
            &account.label,
            &result.status,
            result.points,
            &result.message,
        )) {
            eprintln!("保存签到记录失败：{err}");
            return false;
        }
    }
    recorded
}

/// 落流水判定：成功当天去重、失败 10 分钟节流、已签/跳过不落。
fn should_record_status(status: &str, has_success_today: bool, recent_failure: bool) -> bool {
    match status {
        "success" => !has_success_today,
        "failed" => !recent_failure,
        _ => false,
    }
}

/// 同步一个账号：刷新签到状态 + 积分（落快照）+ 账号资料（补真实昵称）。
///
/// 单个账号失败不影响其他账号，返回签到状态和额度是否都同步成功。
async fn sync_one(app: &AppHandle, state: &AppState, account: &Account) -> bool {
    let Some(provider) = state.provider(&account.provider) else {
        return false;
    };
    let store = state.store.lock().unwrap().clone();
    let Ok(cred) = store.credential(&account.provider, &account.id) else {
        return false;
    };
    let cred = ensure_fresh_cred(state, account, &cred).await;

    // 签到状态（失败不致命，UI 里仍以 overview 的结果为准）
    let status = provider.status(account, &cred).await;
    if let Ok(status) = &status {
        // 「不代领」的平台（Zcode）：出现可领取的套餐时提醒一次
        notify_claim_reminder(app, provider.as_ref(), account, status);
    }

    // 积分 + 落一条快照（趋势图用）
    let quota = provider.quota(account, &cred).await;
    if let Ok(q) = &quota {
        let _ = quota_history::append(&quota_history::QuotaSnapshot::new(
            &account.provider,
            &account.id,
            &account.label,
            q.total_remaining,
            q.total_granted,
            q.total_consumed,
        ));
        maybe_notify_quota(app, state, provider.display_name(), account, q);
    }

    // 账号资料：只有兜底 label 才去换真实昵称
    if account.label_is_fallback() {
        if let Ok(Some(profile)) = provider.profile(account, &cred).await {
            if let Some(name) = profile
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let mut renamed = account.clone();
                renamed.label = name.to_string();
                let mut guard = state.store.lock().unwrap();
                let _ = guard.touch(renamed);
            }
        }
    }

    status.is_ok() && quota.is_ok()
}

/// 调度器后台循环。
///
/// 每 30 秒一轮，做三件事：
///   1. 跨天时重排计划（各 agent 用自己的时间窗）；
///   2. 到点的账号执行签到（受「签到总闸」控制）；
///   3. 按 agent 自己的间隔自动同步积分 / 签到状态 / 账号资料
///      （受「自动同步」开关控制）。**跨天时不看间隔，强制同步一次**，
///      这样「今天已签 / 今天可签」不会停在昨天的状态。
pub async fn scheduler_loop(app: AppHandle) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let state = match app.try_state::<AppState>() {
            Some(s) => s,
            None => continue,
        };

        let config = state.config.lock().unwrap().clone();

        let today = scheduler::today();
        let now_minute = scheduler::now_minute();
        let now_ts = chrono::Local::now().timestamp();

        // 按 agent 分组：每个 agent 有自己独立的时间窗
        let accounts = state.store.lock().unwrap().list();
        let mut window_by_provider: BTreeMap<String, (u32, u32)> = BTreeMap::new();
        for account in &accounts {
            if !window_by_provider.contains_key(&account.provider) {
                let cfg = config.scheduler.agent(&account.provider);
                window_by_provider
                    .insert(account.provider.clone(), (cfg.start_minute, cfg.end_minute));
            }
        }

        let keys: Vec<String> = accounts
            .iter()
            .map(|a| AccountStore::key(&a.provider, &a.id))
            .collect();

        // 跨天检测：计划日期不是今天就说明过了一天
        let day_changed = {
            let sched = state.scheduler.lock().unwrap();
            sched.date != today
        };

        // 跨天重排计划（各 agent 用自己的时间窗）
        {
            let mut sched = state.scheduler.lock().unwrap();
            for (provider, (start, end)) in &window_by_provider {
                let provider_keys: Vec<String> = accounts
                    .iter()
                    .filter(|a| &a.provider == provider)
                    .map(|a| AccountStore::key(&a.provider, &a.id))
                    .collect();
                sched.roll_over(&today, &provider_keys, *start, *end);
            }
            // 统一清理：只保留仍然存在的账号
            sched.prune(&keys);
            let _ = sched.save();
        }

        // ---- 到点签到（受「签到总闸」控制）----
        let mut changed = false;
        if config.scheduler.enabled {
            for account in accounts.clone() {
                // 每个 agent 自己管自己的开关
                let agent_cfg = config.scheduler.agent(&account.provider);
                if !agent_cfg.enabled || !agent_cfg.is_valid() {
                    continue;
                }
                // 只展示 + 提醒的平台（Zcode）不参与自动领取：
                // 领取要过官方客户端的阿里云验证码，第三方做不了。
                if !state
                    .provider(&account.provider)
                    .map(|p| p.supports_claim())
                    .unwrap_or(false)
                {
                    continue;
                }

                let key = AccountStore::key(&account.provider, &account.id);
                let (done, minute, catch_up_attempted) = {
                    let sched = state.scheduler.lock().unwrap();
                    (
                        sched.is_done(&key, &today),
                        sched.minute_of(&key).unwrap_or(u32::MAX),
                        sched.is_catch_up_attempted(&key, &today),
                    )
                };
                if minute == u32::MAX {
                    continue;
                }
                let decision = scheduler::decide_run(
                    now_minute,
                    minute,
                    agent_cfg.end_minute,
                    done,
                    config.scheduler.catch_up_missed_window,
                    catch_up_attempted,
                );
                if decision == scheduler::RunDecision::Skip {
                    continue;
                }
                let is_catch_up = decision == scheduler::RunDecision::CatchUp;

                let Some(provider) = state.provider(&account.provider) else {
                    continue;
                };
                let Ok(_running) = state.checkin_running.try_lock() else {
                    break;
                };
                let cred = match state
                    .store
                    .lock()
                    .unwrap()
                    .credential(&account.provider, &account.id)
                {
                    Ok(c) => c,
                    Err(e) => {
                        let result = AccountResult {
                            account_id: account.id.clone(),
                            provider: account.provider.clone(),
                            label: account.label.clone(),
                            status: "failed".into(),
                            points: 0,
                            message: e.to_string(),
                        };
                        // 走 record_result：失败有 10 分钟节流，避免 30 秒一轮刷屏
                        changed |= record_result(&account, &result);
                        notify_checkin_failure(
                            &app,
                            provider.display_name(),
                            &account,
                            &result,
                            &today,
                        );
                        continue;
                    }
                };
                // 自动签到多在早上跑，非当前登录账号的 token（1 小时寿命）必然已过期 ——
                // 签到前先刷新凭据，否则永远签不上
                let cred = ensure_fresh_cred(&state, &account, &cred).await;

                let result = run_checkin(provider.as_ref(), &account, &cred).await;

                // 「skipped」= 上游今天还没开窗。既**不能标记成已处理**
                //（否则一整天都不再重试），也不值得落流水 ——
                // 否则一个时间窗内会刷出几十条没有信息量的记录。
                let opened = result.status == "success" || result.status == "already";
                changed |= record_result(&account, &result);
                notify_checkin_failure(&app, provider.display_name(), &account, &result, &today);

                let mut sched = state.scheduler.lock().unwrap();
                // 时间窗外的补跑每天只尝试一次：失败也记「已补过」，
                // 避免调度器 30 秒一轮持续打上游；用户仍可手动补签。
                if is_catch_up {
                    sched.mark_catch_up_attempted(&key, &today);
                }
                if opened {
                    sched.mark_done(&key, &today);
                }
                let _ = sched.save();
            }
        }

        // ---- 自动同步（积分 / 状态 / 资料）----
        if config.scheduler.sync_enabled {
            let Ok(_running) = state.sync_running.try_lock() else {
                if changed {
                    let _ = app.emit("accounts-changed", ());
                }
                continue;
            };
            // 每个 agent 距上次同步多久了
            let last_sync: BTreeMap<String, i64> = {
                let sched = state.scheduler.lock().unwrap();
                state
                    .providers
                    .iter()
                    .map(|p| (p.id().to_string(), sched.last_sync_of(p.id()).unwrap_or(0)))
                    .collect()
            };

            let mut synced_providers: Vec<String> = Vec::new();
            for provider in state.providers.iter() {
                let list: Vec<Account> = accounts
                    .iter()
                    .filter(|a| a.provider == provider.id())
                    .cloned()
                    .collect();
                if list.is_empty() {
                    continue;
                }
                let interval_secs = config.refresh_interval_of(provider.id()) as i64 * 60;
                let elapsed = now_ts - last_sync.get(provider.id()).copied().unwrap_or(0);
                // 跨天强制同步；否则按各自间隔
                if !day_changed && elapsed < interval_secs {
                    continue;
                }
                for account in &list {
                    sync_one(&app, &state, account).await;
                }
                synced_providers.push(provider.id().to_string());
            }

            if !synced_providers.is_empty() {
                let mut sched = state.scheduler.lock().unwrap();
                for pid in &synced_providers {
                    sched.mark_synced(pid, now_ts);
                }
                let _ = sched.save();
                changed = true;
            }
        }
        if changed {
            let _ = app.emit("accounts-changed", ());
        }
    }
}

// ---------------------------------------------------------------------------
// 命令行入口（不启 GUI）
//
// 界面里的「从本机导入」和「添加账号」需要点按钮，在无界面 / 自动化场景下
// 用不了，所以补两个等价命令：
//   CheckinBox --import-local              导入本机客户端登录态
//   CheckinBox --device-auth qoder
// ---------------------------------------------------------------------------

/// 把所有「读本机客户端登录态」的平台账号导入账号池
/// （MiniMax / Qoder / 妙手 / WorkBuddy / Zcode）。
pub fn cli_import_local() -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let state = AppState::new();
        let mut body = String::new();
        if let Some(warning) = &state.store_warning {
            body.push_str(&format!("注意：{warning}\n\n"));
        }
        let providers: Vec<Arc<dyn Provider>> = state
            .providers
            .iter()
            .filter(|p| matches!(p.id(), "minimax" | "qoder" | "miaoshou" | "workbuddy" | "zcode" | "trae" | "doubaowork"))
            .cloned()
            .collect();

        let mut imported = 0usize;
        let mut failed = 0usize;
        for provider in providers {
            match provider.discover().await {
                Ok(found) if found.is_empty() => {
                    body.push_str(&format!(
                        "{}：本机客户端没有登录态\n",
                        provider.display_name()
                    ));
                }
                Ok(found) => {
                    for (mut account, cred) in found {
                        let mut store = state.store.lock().unwrap();
                        if account.provider == "workbuddy" {
                            reuse_workbuddy_pool_id(&store, &mut account);
                        } else if account.provider == "qoder" {
                            reuse_qoder_pool_id(&store, &mut account);
                        }
                        match store.upsert(account.clone(), &cred) {
                            Ok(()) => {
                                imported += 1;
                                body.push_str(&format!(
                                    "已导入 {} · {}\n",
                                    provider.display_name(),
                                    account.label
                                ));
                            }
                            Err(e) => {
                                failed += 1;
                                body.push_str(&format!(
                                    "{} · {} 写入失败：{e}\n",
                                    provider.display_name(),
                                    account.label
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    body.push_str(&format!("{} 发现失败：{e}\n", provider.display_name()));
                }
            }
        }
        body.push_str(&format!("\n共导入 {imported} 个账号。\n"));
        body.push_str(&format!(
            "账号池文件：{}\n",
            crate::core::paths::accounts_file().display()
        ));
        body.push_str(
            "若导入前 CheckinBox 正在运行，请退出后重新打开——运行中的界面不会自动加载本次导入。\n",
        );
        cli_show("导入本机客户端登录态", &body);
        if imported == 0 && failed > 0 {
            return Err("导入失败，详见结果文件".into());
        }
        Ok(())
    })
}

/// 命令行结果落盘并打开。
///
/// release 版是 `windows_subsystem = "windows"`（不弹控制台），`println!`
/// 的内容用户根本看不见。换号备份类命令用 `cli_emit` 写到按平台的备份目录；
/// 导入这类跨平台命令用这里写到数据目录根下。
fn cli_show(title: &str, body: &str) {
    println!("{title}\n{body}");
    let dir = crate::core::paths::data_dir();
    if std::fs::create_dir_all(&dir).is_ok() {
        let out = dir.join("_cli-output.txt");
        if std::fs::write(&out, format!("{title}\n{body}\n")).is_ok() {
            let _ = std::process::Command::new("explorer.exe")
                .arg(&out)
                .spawn();
        }
    }
}

/// 命令行输出。
///
/// release 版是 `windows_subsystem = "windows"`（不弹控制台），
/// `println!` 的内容用户根本看不见 —— 所以同时写一份文件到备份目录，
/// 再用系统默认程序打开，用户能直接看到结果。
fn cli_emit(provider: &str, title: &str, body: &str) {
    println!("{title}\n{body}");
    let dir = crate::core::client_backup::backup_root(provider);
    if std::fs::create_dir_all(&dir).is_ok() {
        let out = dir.join("_cli-output.txt");
        if std::fs::write(&out, format!("{title}\n{body}\n")).is_ok() {
            let _ = std::process::Command::new("explorer.exe")
                .arg(&out)
                .spawn();
        }
    }
}

/// 命令行版：列出客户端登录态的多代备份。
///   CheckinBox --list-client-backups <minimax|miaoshou|qoder>
pub fn cli_list_client_backups(provider: &str) -> Result<(), String> {
    let list = crate::core::client_backup::list_client_login_backups(provider);
    if list.is_empty() {
        cli_emit(provider, "{provider} 没有客户端登录态备份", "");
        return Ok(());
    }
    let mut body = String::new();
    for b in list {
        let when = chrono::DateTime::from_timestamp_millis(b.created_at_ms)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        body.push_str(&format!("{}  {}  {}  {}  {}\n", b.op_id, when, b.reason, b.bytes, b.dir));
        for f in &b.source_files {
            body.push_str(&format!("      <- {f}\n"));
        }
    }
    cli_emit(provider, &format!("{provider} 的客户端登录态备份（新→旧）："), &body);
    Ok(())
}

/// 命令行版：回滚到指定的一代客户端登录态备份。
///   CheckinBox --restore-client-backup <minimax|miaoshou|qoder> <操作id>
pub fn cli_restore_client_backup(provider: &str, op_id: &str) -> Result<(), String> {
    crate::core::client_backup::restore_client_login_backup(provider, op_id)?;
    cli_emit(
        provider,
        &format!("已回滚 {provider} 的客户端登录态到 {op_id}"),
        "回滚前的现场已另存一代；请重启客户端确认登录的是预期账号。",
    );
    Ok(())
}

/// 命令行版：把客户端切换成指定账号（关客户端 → 捕获 → 保活 → 写入 → 启动）。
///
/// 用途：脚本里切账号，或者界面点不动时的兜底。
///   CheckinBox --switch-client <minimax|miaoshou> <account_id>
pub async fn cli_switch_client(provider_id: &str, account_id: &str) -> Result<(), String> {
    let state = AppState::new();
    let store = state.store.lock().unwrap().clone();
    let account = store
        .list_of(provider_id)
        .into_iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("账号不存在：{account_id}"))?;
    let cred = store
        .credential(provider_id, account_id)
        .map_err(|e| e.to_string())?;
    let cred = prepare_switch_cred(&state, &account, cred).await?;

    // 与界面路径同序：先关客户端，再捕获（拿它最后提交的凭据），再保活
    let was_running = crate::core::launcher::is_running(provider_id);
    crate::core::client_switch::begin_switch(provider_id).map_err(|e| e.to_string())?;
    capture_client_login(&state, provider_id).await;
    let cred = match switch_cred_guard(&state, &account, cred).await {
        Ok(cred) => cred,
        Err(e) => {
            if was_running {
                let _ = crate::core::launcher::launch(provider_id);
            }
            return Err(e);
        }
    };

    // CLI 同样尊重配置里的「同步聊天记录」开关
    let chat_sync_enabled = state
        .config
        .lock()
        .unwrap()
        .scheduler
        .agent(provider_id)
        .chat_sync_enabled;
    let mut report_progress = |_: &str| {};
    let out = crate::core::client_switch::finish_switch(
        provider_id,
        &cred,
        account_id,
        &account.label,
        chat_sync_enabled,
        &mut report_progress,
    )
    .map_err(|e| e.to_string())?;

    println!("已把 {} 的客户端账号切换成 {}", provider_id, account.label);
    println!("  写入凭据: {}", out.target_file);
    if let Some(bak) = out.backup {
        println!("  原登录态备份: {bak}");
    }
    if let Some(chat) = out.chat_sync {
        println!("  聊天记录: {}", chat.detail);
    }
    println!("  客户端: {}", out.client_exe);
    Ok(())
}

/// 命令行版的设备授权：发起会话、落盘、打印授权地址。
///
/// **不在这里轮询** —— 轮询交给应用本身：会话写进 `auth_pending.json`，
/// 应用启动时会读回来接着轮询（和界面里「等待授权」那条提示是同一条路径）。
/// 命令行进程在后台容易被收掉，让它长时间轮询不可靠。
pub fn cli_device_auth(provider_id: &str) -> Result<(), String> {
    let state = AppState::new();
    // MiniMax 走 OAuth 设备授权（异步）；Qoder 走自家登录页（同步）。
    // 之前 CLI 只放行 qoder —— 恢复「RT 已被吊销」的账号时缺一条不依赖客户端
    // 的路（2026-10-27 补上，与 begin_device_auth 命令的字段映射保持一致）。
    let session = match provider_id {
        "minimax" => {
            let d = tauri::async_runtime::block_on(state.minimax.begin_device_authorization())
                .map_err(|e| e.to_string())?;
            AuthSession {
                id: uuid::Uuid::new_v4().to_string(),
                provider: provider_id.to_string(),
                auth_url: d.auth_url,
                verifier: d.code_verifier,
                nonce: d.poll_code,
                machine_id: String::new(),
                created_at: chrono::Utc::now().timestamp(),
                extra: serde_json::json!({
                    "poll_param": d.poll_param, "interval": d.interval_secs
                }),
            }
        }
        "qoder" => state
            .qoder
            .begin_authorization(provider_id)
            .map_err(|e| e.to_string())?,
        other => return Err(format!("不支持设备授权：{other}")),
    };

    let mut sessions = load_pending_auth();
    sessions.insert(session.id.clone(), session.clone());
    save_pending_auth(&sessions);

    println!("授权地址：{}", session.auth_url);
    println!(
        "已登记为待完成会话（provider={}）。启动应用后会显示「等待授权」提示并自动轮询，",
        session.provider
    );
    println!("在浏览器里打开上面的地址，用要登录的账号点「确认授权」即可。");
    Ok(())
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn account(id: &str) -> Account {
        Account {
            id: id.to_string(),
            provider: "minimax".to_string(),
            label: id.to_string(),
            created_at: 0,
            last_used: None,
            origin: "test".to_string(),
        }
    }

    #[test]
    fn 浏览器旧账号以真实uid匹配但保留原有记录() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let mut old = account("legacy-token-fingerprint");
        old.provider = "workbuddy".into();
        old.created_at = 100;
        let plain = serde_json::to_vec(&json!({"uid": "real-uid"})).unwrap();
        let cipher = crate::core::dpapi::protect(&plain).unwrap();
        let mut store = AccountStore::default();
        store.accounts.insert(
            AccountStore::key("workbuddy", &old.id),
            crate::core::store::StoredAccount {
                account: old.clone(),
                credential: STANDARD.encode(cipher),
            },
        );

        let mut reimported = account("real-uid");
        reimported.provider = "workbuddy".into();
        reuse_workbuddy_pool_id(&store, &mut reimported);
        assert_eq!(reimported.id, old.id);
        assert_eq!(reimported.created_at, old.created_at);
        assert!(workbuddy_pool_account(&store, "unrelated-uid").is_none());
    }

    #[test]
    fn qoder_recovered_identity_reuses_only_its_own_legacy_record() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let mut old = account(&qoder::account_id(""));
        old.provider = "qoder".into();
        old.created_at = 100;
        let real_uid = "recovered-qoder-uid";
        let plain = serde_json::to_vec(&json!({"user_id": real_uid})).unwrap();
        let cipher = crate::core::dpapi::protect(&plain).unwrap();
        let mut store = AccountStore::default();
        store.accounts.insert(
            AccountStore::key("qoder", &old.id),
            crate::core::store::StoredAccount {
                account: old.clone(),
                credential: STANDARD.encode(cipher),
            },
        );
        let mut reimported = account(&qoder::account_id(real_uid));
        reimported.provider = "qoder".into();
        reuse_qoder_pool_id(&store, &mut reimported);
        assert_eq!(reimported.id, old.id);
        assert_eq!(reimported.created_at, old.created_at);
        assert!(qoder_legacy_pool_id(&store, &qoder::account_id("other-uid")).is_none());
    }

    #[tokio::test]
    #[ignore = "依赖已登录的 WorkBuddy 客户端和本机 Cockpit 账号库，只读"]
    async fn workbuddy_client_import_uses_current_session() {
        let provider = workbuddy::WorkBuddyProvider::new();
        let records = discover_client_accounts(&provider).await.unwrap();
        assert_eq!(records.len(), 1);
        let (account, _) = &records[0];
        let detected = crate::core::client_switch::detect("workbuddy")
            .unwrap()
            .expect("WorkBuddy 客户端当前未登录");
        // 常规检测用明文 UID，导入会解密昵称，因此按 UID 比对。
        assert!(account.id == detected.account_id);
        assert_eq!(account.origin, "WorkBuddy 客户端登录态");
        eprintln!("WorkBuddy 本机导入账号：{}", account.label);
    }

    #[test]
    fn 剩余时间充足就不刷新_临过期才刷() {
        let now = 1_000_000i64;
        // 还剩 1 小时 → 不刷
        assert!(!needs_refresh(
            &json!({ "expires_at_ms": now + 3_600_000 }),
            now
        ));
        // 还剩 4 分钟（< 5 分钟缓冲）→ 刷
        assert!(needs_refresh(
            &json!({ "expires_at_ms": now + 4 * 60_000 }),
            now
        ));
        // 正好 5 分钟 → 刷
        assert!(needs_refresh(
            &json!({ "expires_at_ms": now + 5 * 60_000 }),
            now
        ));
        // 已过期 → 刷
        assert!(needs_refresh(&json!({ "expires_at_ms": now - 1_000 }), now));
    }

    #[test]
    fn 凭据里没有过期时间就当已过期处理() {
        // 老凭据没这个字段时宁可多刷一次，也不要因为"看着没过期"而永远不刷
        assert!(needs_refresh(&json!({ "access_token": "x" }), 0));
        assert!(needs_refresh(&serde_json::Value::Null, 0));
    }

    #[test]
    fn qoder临期才刷新_未知到期不主动刷新() {
        let now = 1_000_000i64;
        // 还剩 1 小时 → 不刷
        assert!(!qoder_needs_refresh(
            &json!({ "expires_at": now + 3_600_000 }),
            now
        ));
        // 还剩 4 分钟 → 刷
        assert!(qoder_needs_refresh(
            &json!({ "expires_at": now + 4 * 60_000 }),
            now
        ));
        // 已过期 → 刷
        assert!(qoder_needs_refresh(&json!({ "expires_at": now - 1 }), now));
        // 没给到期时间 → 不主动刷（避免每轮同步都换一次 RT）
        assert!(!qoder_needs_refresh(&json!({ "access_token": "x" }), now));
        assert!(!qoder_needs_refresh(&json!({ "expires_at": 0 }), now));
    }

    #[tokio::test]
    async fn 同一账号共用一把刷新锁_不同账号各一把() {
        // single-flight 的基础：同一账号的并发刷新必须拿到同一把锁
        let a1 = refresh_lock_for(&account("a")).await;
        let a2 = refresh_lock_for(&account("a")).await;
        assert!(Arc::ptr_eq(&a1, &a2), "同一账号应该复用同一把锁");

        let b = refresh_lock_for(&account("b")).await;
        assert!(!Arc::ptr_eq(&a1, &b), "不同账号不该共用锁");
    }

    #[tokio::test]
    async fn 同一账号的并发刷新会串行_不会同时进临界区() {
        let lock = refresh_lock_for(&account("race")).await;
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // 先占住锁，第二个任务必须等它释放
        let first = lock.lock().await;
        let lock2 = lock.clone();
        let entered2 = entered.clone();
        let waiter = tokio::spawn(async move {
            let _g = lock2.lock().await;
            entered2.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            !entered.load(std::sync::atomic::Ordering::SeqCst),
            "锁没释放时不该放第二个进来"
        );

        drop(first);
        waiter.await.unwrap();
        assert!(
            entered.load(std::sync::atomic::Ordering::SeqCst),
            "释放锁后第二个任务应该能进来"
        );
    }

    #[test]
    fn 流水规则_成功去重_失败节流_已签跳过不记() {
        use super::should_record_status as s;
        // 成功：当天还没有记录 → 记
        assert!(s("success", false, false));
        // 成功：当天已经记过 → 去重，不再追加
        assert!(!s("success", true, false));
        // 失败：可以记，但 10 分钟内已有失败时节流（调度器 30 秒一试不能刷屏）
        assert!(s("failed", false, false));
        assert!(!s("failed", false, true));
        // 已签 / 跳过：不落流水
        assert!(!s("already", false, false));
        assert!(!s("skipped", false, false));
    }

    #[test]
    fn qoder本地领取_按天去重并计算到期() {
        use chrono::TimeZone;

        let mut qoder = account("q1");
        qoder.provider = "qoder".into();
        let entry = |id: &str, date: &str, ts: &str, points: i64, msg: &str| LogEntry {
            id: id.into(),
            timestamp: ts.into(),
            date: date.into(),
            provider: "qoder".into(),
            account_id: "q1".into(),
            label: "Q".into(),
            status: "success".into(),
            points,
            message: msg.into(),
        };
        let logs = vec![
            entry(
                "1",
                "2026-10-30",
                "2026-10-30 10:00:00",
                100,
                "签到成功 +100 Credits，30 天有效",
            ),
            entry(
                "2",
                "2026-10-30",
                "2026-10-30 10:05:00",
                100,
                "同一天重复记录",
            ),
            entry(
                "3",
                "2026-10-29",
                "2026-10-29 10:00:00",
                100,
                "签到成功 +100 Credits，30 天有效",
            ),
            entry("4", "2026-10-28", "2026-10-28 10:00:00", 0, "没有积分"),
        ];
        let now = chrono::Local
            .with_ymd_and_hms(2026, 11, 1, 12, 0, 0)
            .single()
            .unwrap()
            .timestamp_millis();
        let grants = qoder_tracked_grants(&logs, &qoder, now);
        assert_eq!(grants.len(), 2, "同一天只保留一条、0 积分不计");
        assert!(grants
            .iter()
            .all(|g| g.expire_at_ms - g.granted_at_ms == 30 * 86_400_000));
        assert_eq!(qoder_valid_days("签到成功 +100 Credits，15 天有效"), 15);
        assert_eq!(qoder_valid_days("没有有效期信息"), 30);
    }
}
