//! 豆包工作（DoubaoWork）适配器。
//!
//! 核心能力：
//!   1. 多账号自动发现：自动扫描 `%LOCALAPPDATA%\Doubao\User Data`（或 `DoubaoWork`），
//!      解密 Chrome/aha 框架 DPAPI + AES-256-GCM 保护的 Cookies 数据库，
//!      并通过硬件签名剥离算法还原纯净的 `sessionid`。
//!   2. 身份与额度核验：调用 `identity.doubao.com` 获取用户真名、真实 UID、手机号与套餐状态。
//!   3. 每日自动签到：支持周一翻倍奖励（平时 +200，周一 +400）自动领取与状态核验。
//!   4. 多账号无损换号：支持修改 `Local State` 的 `last_used` 并带 `--profile-directory` 启动。

use std::path::{Path, PathBuf};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::core::os_crypt;
use crate::core::provider::{
    Account, AccountProfile, CheckinStatus, ClaimOutcome, ClaimState, CreditItem, Provider, Quota,
};

const ORIGIN: &str = "https://www.doubao.com";
const CAMPAIGN_PARAMS: &str = "version_code=20800&language=zh&device_platform=web&doubao_device_platform=web&aid=497858&real_aid=497858&pkg_type=release";

pub struct DoubaoWorkProvider {
    http: reqwest::Client,
}

impl DoubaoWorkProvider {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 SamanthaDoubao/2.37.16")
            .build()
            .unwrap_or_default();
        Self { http }
    }
}

/// 查找本机豆包工作 User Data 目录
pub fn find_doubao_user_data() -> Option<PathBuf> {
    let local = dirs::data_local_dir()?;
    let p1 = local.join("Doubao").join("User Data");
    if p1.is_dir() {
        return Some(p1);
    }
    let p2 = local.join("DoubaoWork").join("User Data");
    if p2.is_dir() {
        return Some(p2);
    }
    None
}

/// 安全复制文件，支持被占用（共享读写模式）
fn safe_copy_file(src: &Path, dst: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(7) // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        .open(src)?;

    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)?;

    std::io::copy(&mut file, &mut out)?;
    Ok(())
}

/// 从 Profile 的 Cookies SQLite 数据库中读取 doubao.com 相关凭据
fn read_profile_cookies(profile_dir: &Path, key: &[u8; 32]) -> Result<String> {
    let cookies_path = profile_dir.join("Network").join("Cookies");
    if !cookies_path.is_file() {
        return Err(anyhow!("Cookies 文件不存在"));
    }

    let temp_dir = tempfile::tempdir()?;
    let temp_db_path = temp_dir.path().join("Cookies");
    let mut copied = false;
    for _ in 0..5 {
        if safe_copy_file(&cookies_path, &temp_db_path).is_ok() {
            copied = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !copied {
        return Err(anyhow!("无法读取正在被占用的 Cookies 文件"));
    }

    let conn = Connection::open_with_flags(
        &temp_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;

    let mut stmt = conn.prepare(
        "SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE '%doubao.com%'",
    )?;

    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let value: String = row.get(1)?;
        let enc_val: Vec<u8> = row.get(2)?;
        Ok((name, value, enc_val))
    })?;

    let mut cookies = Vec::new();

    for r in rows.flatten() {
        let (name, val, enc) = r;
        let final_val = if !val.is_empty() {
            val
        } else if enc.starts_with(b"v10") || enc.starts_with(b"v11") {
            if let Ok(dec) = os_crypt::decrypt(key, &enc) {
                // aha 框架硬件签名前缀剥离算法：
                // 若前 32 字节包含二进制硬件签名，且后续 32 字节全为合法 ASCII/HEX，则提取尾部
                if dec.len() >= 64 && dec.iter().take(16).any(|&b| b < 0x20 || b > 0x7e) {
                    let tail = &dec[dec.len() - 32..];
                    if tail.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
                        String::from_utf8_lossy(tail).to_string()
                    } else {
                        String::from_utf8_lossy(&dec).to_string()
                    }
                } else if dec.len() > 32 && dec[..32].iter().any(|&b| b < 0x20 || b > 0x7e) {
                    let rest = &dec[32..];
                    if rest.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
                        String::from_utf8_lossy(rest).to_string()
                    } else {
                        String::from_utf8_lossy(&dec).to_string()
                    }
                } else {
                    String::from_utf8_lossy(&dec).to_string()
                }
            } else {
                continue;
            }
        } else {
            continue;
        };

        let clean_val: String = final_val.chars().filter(|c| !c.is_control() && *c != ';' && *c != '\r' && *c != '\n').collect();
        if !clean_val.is_empty() {
            cookies.push(format!("{}={}", name, clean_val));
        }
    }

    Ok(cookies.join("; "))
}

#[async_trait]
impl Provider for DoubaoWorkProvider {
    fn id(&self) -> &'static str {
        "doubaowork"
    }

    fn display_name(&self) -> &'static str {
        "豆包工作"
    }

    fn accent(&self) -> &'static str {
        "#0057FF"
    }

    fn docs_url(&self) -> &'static str {
        "https://www.doubao.com/pc/agent-explore"
    }

    async fn discover(&self) -> Result<Vec<(Account, Value)>> {
        let user_data = match find_doubao_user_data() {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };

        let local_state_path = user_data.join("Local State");
        if !local_state_path.is_file() {
            return Ok(Vec::new());
        }

        let key = os_crypt::read_key(&local_state_path)?;
        let state_bytes = std::fs::read(&local_state_path)?;
        let state_json: Value = serde_json::from_slice(&state_bytes)?;

        let info_cache = state_json["profile"]["info_cache"]
            .as_object()
            .cloned()
            .unwrap_or_default();

        let mut discovered = Vec::new();
        let now_ms = chrono::Utc::now().timestamp_millis();

        for (dir_name, info) in info_cache {
            let profile_dir = user_data.join(&dir_name);
            if !profile_dir.is_dir() {
                continue;
            }

            let cookie_header = match read_profile_cookies(&profile_dir, &key) {
                Ok(c) if !c.is_empty() => c,
                _ => continue,
            };

            // 验证是否包含核心登录凭据 sessionid
            if !cookie_header.contains("sessionid=") {
                continue;
            }

            // 调用 identity 接口验证有效性与换取用户信息
            let ident_url = format!(
                "{}/passport/account/info/v2/?account_sdk_source=web&sdk_version=2.2.5&aid=582478&real_aid=582478&device_platform=web&samantha_web=1&use-olympus-account=1",
                ORIGIN
            );
            let ident_resp = self.http.get(&ident_url)
                .header("Cookie", &cookie_header)
                .header("Origin", ORIGIN)
                .header("Referer", format!("{}/chat/", ORIGIN))
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
                .send()
                .await;

            match ident_resp {
                Ok(resp) => {
                    if let Ok(body) = resp.json::<Value>().await {
                        if body["message"].as_str() == Some("success") {
                            let d = &body["data"];
                            let uid_str = d["user_id_str"].as_str().unwrap_or("");
                            let uid_num = d["user_id"].as_i64().unwrap_or(0);
                            let real_uid = if !uid_str.is_empty() {
                                uid_str.to_string()
                            } else if uid_num > 0 {
                                uid_num.to_string()
                            } else {
                                String::new()
                            };

                            if !real_uid.is_empty() {
                                let user_name = d["name"].as_str().unwrap_or("").to_string();
                                let mobile = d["mobile"].as_str().unwrap_or("").to_string();
                                let cache_name = info["name"].as_str().unwrap_or("").to_string();

                                let label = if !user_name.is_empty() {
                                    user_name.clone()
                                } else if !cache_name.is_empty() {
                                    cache_name
                                } else if !mobile.is_empty() {
                                    mobile.clone()
                                } else {
                                    format!("豆包用户_{}", &real_uid[real_uid.len().saturating_sub(4)..])
                                };

                                let account = Account {
                                    id: real_uid.clone(),
                                    provider: "doubaowork".into(),
                                    label,
                                    created_at: now_ms,
                                    last_used: Some(now_ms),
                                    origin: format!("本机客户端 ({})", dir_name),
                                };

                                let cred = json!({
                                    "userId": real_uid,
                                    "userName": user_name,
                                    "mobile": mobile,
                                    "profileDir": dir_name,
                                    "cookieHeader": cookie_header,
                                });

                                // 同一账号去重：优先保留顶层 profile（如 Profile 3，而非 aha\users\...\profile_explorer）
                                if let Some(pos) = discovered.iter().position(|(a, _): &(Account, Value)| a.id == real_uid) {
                                    let (_, old_cred) = &discovered[pos];
                                    let old_dir = old_cred["profileDir"].as_str().unwrap_or("");
                                    let is_old_nested = old_dir.contains('\\') || old_dir.contains('/');
                                    let is_new_nested = dir_name.contains('\\') || dir_name.contains('/');
                                    if is_old_nested && !is_new_nested {
                                        discovered[pos] = (account, cred);
                                    }
                                } else {
                                    discovered.push((account, cred));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("    [doubaowork] {} ident 请求失败: {:?}", dir_name, e);
                }
            }
        }

        Ok(discovered)
    }

    async fn status(&self, _account: &Account, cred: &Value) -> Result<CheckinStatus> {
        let cookie_header = cred["cookieHeader"].as_str().unwrap_or("");
        if cookie_header.is_empty() {
            return Ok(CheckinStatus {
                state: ClaimState::Unknown,
                message: "缺少 Cookie 凭据，请重新导入".into(),
                ..Default::default()
            });
        }

        let detail_url = format!("{}/alice/ug/campaign/v3/detail/?{}", ORIGIN, CAMPAIGN_PARAMS);
        let resp = self.http.post(&detail_url)
            .header("Cookie", cookie_header)
            .header("Origin", ORIGIN)
            .header("Referer", format!("{}/pc/agent-explore", ORIGIN))
            .header("Content-Type", "application/json")
            .json(&json!({ "campaign_group_code": "pc_incentive_task_mvp_v3" }))
            .send()
            .await?;

        let body: Value = resp.json().await.unwrap_or_default();
        let tasks = body["data"]["tasks"].as_array();
        let sign_task = tasks.and_then(|arr| {
            arr.iter().find(|t| t["campaign_code"].as_str() == Some("daily_signin"))
        });

        if let Some(task) = sign_task {
            let status_code = task["task_status"].as_i64().unwrap_or(0);
            let daily = &task["daily_checkin"];
            let checked_in_today = daily["checked_in_today"].as_bool().unwrap_or(false) || status_code == 3;
            let streak_days = daily["continuous_days"].as_i64().unwrap_or(0) as i32;
            let reward_points = daily["reward"]["reward_amount"].as_i64().unwrap_or(200);

            let state = if checked_in_today {
                ClaimState::Claimed
            } else {
                ClaimState::Claimable
            };

            let msg = if checked_in_today {
                format!("今日已签到，已连续签到 {} 天", streak_days)
            } else {
                format!("今日签到可领 +{} 额度", reward_points)
            };

            Ok(CheckinStatus {
                state,
                points: reward_points,
                streak_days,
                message: msg,
                day_index: None,
                bonus_points: 0,
                days: Vec::new(),
            })
        } else {
            Ok(CheckinStatus {
                state: ClaimState::NotAvailable,
                points: 0,
                streak_days: 0,
                message: "未发现每日签到活动".into(),
                ..Default::default()
            })
        }
    }

    async fn claim(&self, _account: &Account, cred: &Value) -> Result<ClaimOutcome> {
        let cookie_header = cred["cookieHeader"].as_str().unwrap_or("");
        if cookie_header.is_empty() {
            return Ok(ClaimOutcome::failed("缺少 Cookie 凭据"));
        }

        let claim_url = format!("{}/alice/ug/campaign/landing/checkin?{}", ORIGIN, CAMPAIGN_PARAMS);
        let resp = self.http.post(&claim_url)
            .header("Cookie", cookie_header)
            .header("Origin", ORIGIN)
            .header("Referer", format!("{}/pc/agent-explore", ORIGIN))
            .header("Content-Type", "application/json")
            .json(&json!({ "scene": "pc_incentive_task_mvp_v3" }))
            .send()
            .await?;

        let body: Value = resp.json().await.unwrap_or_default();
        let code = body["code"].as_i64().unwrap_or(-1);

        if code == 0 {
            let data = &body["data"];
            let reward = data["reward_amount"].as_i64().unwrap_or(200);
            let days = data["continuous_days"].as_i64().unwrap_or(1);
            let idempotent = data["idempotent"].as_bool().unwrap_or(false);

            let msg = if idempotent {
                format!("今日已领过，连续签到 {} 天", days)
            } else {
                format!("签到成功 +{} 额度，连续签到 {} 天", reward, days)
            };

            Ok(ClaimOutcome::claimed(reward, msg))
        } else if code == 710010702 {
            // 服务端暂未开放/稍后重试
            Ok(ClaimOutcome {
                state: ClaimState::Claimable,
                points: 0,
                message: "今日签到暂未对该账号开放（服务端 710010702），可稍后重试".into(),
            })
        } else {
            let err_msg = body["msg"].as_str().or_else(|| body["message"].as_str()).unwrap_or("签到失败");
            Ok(ClaimOutcome::failed(format!("签到失败: {} (code: {})", err_msg, code)))
        }
    }

    async fn quota(&self, _account: &Account, cred: &Value) -> Result<Quota> {
        let cookie_header = cred["cookieHeader"].as_str().unwrap_or("");
        if cookie_header.is_empty() {
            return Ok(Quota::empty("未提供凭据"));
        }

        // 1. 获取套餐情况
        let quota_url = format!("{}/alice/commerce/sale/subscription/overview/", ORIGIN);
        let plan_desc = match self.http.post(&quota_url)
            .header("Cookie", cookie_header)
            .header("Origin", ORIGIN)
            .header("Referer", format!("{}/chat/", ORIGIN))
            .header("Content-Type", "application/json")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
            .json(&json!({ "product_line": "membership" }))
            .send()
            .await
        {
            Ok(r) => {
                let j: Value = r.json().await.unwrap_or_default();
                let data = &j["data"];
                let plan = data["membership_display_name"]
                    .as_str()
                    .or_else(|| data["current_subscription"]["display"]["short_name"].as_str())
                    .unwrap_or("免费体验");
                plan.to_string()
            }
            Err(_) => "免费体验".to_string(),
        };

        // 2. 获取累计获得额度
        let detail_url = format!("{}/alice/ug/campaign/v3/detail/?{}", ORIGIN, CAMPAIGN_PARAMS);
        let (total_points, checked_in) = match self.http.post(&detail_url)
            .header("Cookie", cookie_header)
            .header("Origin", ORIGIN)
            .header("Referer", format!("{}/pc/agent-explore", ORIGIN))
            .header("Content-Type", "application/json")
            .json(&json!({ "campaign_group_code": "pc_incentive_task_mvp_v3" }))
            .send()
            .await
        {
            Ok(r) => {
                let j: Value = r.json().await.unwrap_or_default();
                let amt = j["data"]["progress"]["total_amount"].as_f64().unwrap_or(0.0);
                let tasks = j["data"]["tasks"].as_array();
                let checked = tasks.and_then(|arr| {
                    arr.iter().find(|t| t["campaign_code"].as_str() == Some("daily_signin"))
                }).map(|t| t["task_status"].as_i64().unwrap_or(0) == 3).unwrap_or(false);
                (amt, checked)
            }
            Err(_) => (0.0, false),
        };

        let now_ms = chrono::Utc::now().timestamp_millis();
        let items = vec![CreditItem {
            credit_type: "free".into(),
            granted: total_points,
            consumed: 0.0,
            remaining: total_points,
            granted_at_ms: now_ms,
            expire_at_ms: 0,
            package_name: format!("当前套餐: {}", plan_desc),
            refresh_at_ms: 0,
        }];

        let msg = if checked_in {
            format!("套餐: {} · 累计获得 {} 点 · 今日已签到", plan_desc, total_points as i64)
        } else {
            format!("套餐: {} · 累计获得 {} 点 · 今日未签到", plan_desc, total_points as i64)
        };

        Ok(Quota {
            total_granted: total_points,
            total_consumed: 0.0,
            total_remaining: total_points,
            items,
            message: msg,
            refresh_at_ms: 0,
            credit_groups: Vec::new(),
        })
    }

    async fn profile(&self, _account: &Account, cred: &Value) -> Result<Option<AccountProfile>> {
        let name = cred["userName"].as_str().map(|s| s.to_string());
        let mobile = cred["mobile"].as_str().map(|s| s.to_string());
        Ok(Some(AccountProfile {
            name: name.or(mobile),
            email: None,
            avatar: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_doubaowork_provider_meta() {
        let p = DoubaoWorkProvider::new();
        assert_eq!(p.id(), "doubaowork");
        assert_eq!(p.display_name(), "豆包工作");
        assert_eq!(p.accent(), "#0057FF");
        assert!(p.supports_claim());
    }

    #[test]
    fn test_find_doubao_user_data() {
        // 如果本机安装了豆包工作，应该能定位到
        if let Some(path) = find_doubao_user_data() {
            assert!(path.is_dir());
        }
    }

    #[test]
    fn test_parse_checkin_detail() {
        let mock_json = json!({
            "code": 0,
            "data": {
                "tasks": [
                    {
                        "campaign_code": "daily_signin",
                        "task_status": 1,
                        "daily_checkin": {
                            "checked_in_today": false,
                            "continuous_days": 5,
                            "reward": {
                                "reward_amount": 400
                            }
                        }
                    }
                ],
                "progress": {
                    "total_amount": 1200
                }
            }
        });

        let tasks = mock_json["data"]["tasks"].as_array().unwrap();
        let sign_task = tasks.iter().find(|t| t["campaign_code"].as_str() == Some("daily_signin")).unwrap();
        let status_code = sign_task["task_status"].as_i64().unwrap();
        let daily = &sign_task["daily_checkin"];
        let checked_in_today = daily["checked_in_today"].as_bool().unwrap() || status_code == 3;
        assert!(!checked_in_today);
        assert_eq!(daily["reward"]["reward_amount"].as_i64().unwrap(), 400);
        assert_eq!(daily["continuous_days"].as_i64().unwrap(), 5);
    }
}
