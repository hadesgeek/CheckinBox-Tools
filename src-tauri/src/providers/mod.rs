//! 平台适配器注册表。
//!
//! 新增一个平台 = 在这里加一个 `Provider` 实现 + 在 `all()` 里登记，
//! 另外还要在 `commands.rs::AppState::new()` 的 `providers` 列表里挂上
//! （那才是运行时真正用的列表）。

pub mod doubaowork;
pub mod miaoshou;
pub mod minimax;
pub mod qoder;
pub mod trae;
pub mod workbuddy;
pub mod zcode;

use std::sync::Arc;

use crate::core::provider::Provider;

/// 全部已注册的平台。
#[allow(dead_code)] // 调度器/命令层可按 id 动态取适配器
pub fn all() -> Vec<Arc<dyn Provider>> {
    vec![
        Arc::new(workbuddy::WorkBuddyProvider::new()),
        Arc::new(minimax::MiniMaxProvider::new()),
        Arc::new(trae::TraeProvider::new()),
        Arc::new(qoder::QoderProvider::new()),
        Arc::new(miaoshou::MiaoshouProvider::new()),
        Arc::new(zcode::ZcodeProvider::new()),
        Arc::new(doubaowork::DoubaoWorkProvider::new()),
    ]
}

/// 按 id 取平台。
#[allow(dead_code)] // 调度器/命令层可按 id 动态取适配器
pub fn find(id: &str) -> Option<Arc<dyn Provider>> {
    all().into_iter().find(|p| p.id() == id)
}
