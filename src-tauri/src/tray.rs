//! Windows 托盘的窗口导航和后台操作。

use std::sync::Mutex;

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::{self, AppState};
use crate::notifications::{self, NoticeKind};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowRequest {
    Close,
    Notices,
    Logs,
    Settings,
}

struct TrayState {
    notices: MenuItem<tauri::Wry>,
    checkin: MenuItem<tauri::Wry>,
    sync: MenuItem<tauri::Wry>,
    pending: Mutex<Option<WindowRequest>>,
}

pub fn show_main_window(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        window.show()?;
        window.unminimize()?;
        let _ = window.set_always_on_top(true);
        let _ = window.set_focus();
        let _ = window.set_always_on_top(false);
    }
    Ok(())
}

// 先保留操作，再通知 Webview。刚启动时前端还没注册监听，也能读到操作。
pub fn request_window(app: &AppHandle, request: WindowRequest) {
    *app.state::<TrayState>().pending.lock().unwrap() = Some(request);
    let _ = app.emit("window-requested", ());
}

#[tauri::command]
pub async fn take_window_request(app: AppHandle) -> Option<WindowRequest> {
    app.state::<TrayState>().pending.lock().unwrap().take()
}

pub fn update_unread(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let Ok(count) = handle.state::<AppState>().inbox.unread_count() else {
            return;
        };
        let (label, tooltip) = if count == 0 {
            ("应用内提醒".to_string(), "CheckinBox".to_string())
        } else {
            (
                format!("应用内提醒（{count} 条未读）"),
                format!("CheckinBox · {count} 条未读提醒"),
            )
        };
        let _ = handle.state::<TrayState>().notices.set_text(label);
        if let Some(tray) = handle.tray_by_id("main") {
            let _ = tray.set_tooltip(Some(tooltip));
        }
    });
}

#[derive(Clone, Copy)]
enum TrayTask {
    Checkin,
    Sync,
}

impl TrayTask {
    fn label(self) -> &'static str {
        match self {
            Self::Checkin => "立即签到全部账号",
            Self::Sync => "立即同步账号数据",
        }
    }

    fn menu_item(self, tray: &TrayState) -> &MenuItem<tauri::Wry> {
        match self {
            Self::Checkin => &tray.checkin,
            Self::Sync => &tray.sync,
        }
    }

    fn set_running(self, app: &AppHandle, running: bool) {
        let tray = app.state::<TrayState>();
        let item = self.menu_item(&tray);
        let label = match (self, running) {
            (Self::Checkin, true) => "正在签到…",
            (Self::Sync, true) => "正在同步…",
            (_, false) => self.label(),
        };
        let _ = item.set_text(label);
        let _ = item.set_enabled(!running);
    }

    async fn run(
        self,
        app: &AppHandle,
        state: State<'_, AppState>,
    ) -> Result<(NoticeKind, String), String> {
        let summary = match self {
            Self::Checkin => commands::checkin_all_inner(app, &state).await?,
            Self::Sync => commands::sync_now_inner(app, &state).await?,
        };
        Ok((summary.kind, summary.message))
    }

    fn start(self, app: &AppHandle) {
        self.set_running(app, true);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let (kind, message) = self
                .run(&app, app.state())
                .await
                .unwrap_or_else(|err| (NoticeKind::Err, err));
            if let Err(err) = notifications::publish(&app, kind, self.label(), &message, None) {
                eprintln!("{err}");
                request_window(&app, WindowRequest::Notices);
                let _ = show_main_window(&app);
            }
            self.set_running(&app, false);
        });
    }
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "打开 CheckinBox", true, None::<&str>)?;
    let notices = MenuItem::with_id(app, "notices", "应用内提醒", true, None::<&str>)?;
    let logs = MenuItem::with_id(app, "logs", "签到记录", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "设置", true, None::<&str>)?;
    let checkin = MenuItem::with_id(
        app,
        "checkin",
        TrayTask::Checkin.label(),
        true,
        None::<&str>,
    )?;
    let sync = MenuItem::with_id(app, "sync", TrayTask::Sync.label(), true, None::<&str>)?;
    let hide = MenuItem::with_id(app, "hide", "隐藏主窗口", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出 CheckinBox", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &show,
            &notices,
            &logs,
            &settings,
            &PredefinedMenuItem::separator(app)?,
            &checkin,
            &sync,
            &PredefinedMenuItem::separator(app)?,
            &hide,
            &quit,
        ],
    )?;

    app.manage(TrayState {
        notices,
        checkin,
        sync,
        pending: Mutex::new(None),
    });

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("CheckinBox")
        .on_menu_event(|app, event| {
            let request = match event.id().as_ref() {
                "notices" => Some(WindowRequest::Notices),
                "logs" => Some(WindowRequest::Logs),
                "settings" => Some(WindowRequest::Settings),
                "show" => None,
                "checkin" => return TrayTask::Checkin.start(app),
                "sync" => return TrayTask::Sync.start(app),
                "hide" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                    return;
                }
                "quit" => return app.exit(0),
                _ => return,
            };
            if let Some(request) = request {
                request_window(app, request);
            }
            let _ = show_main_window(app);
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let _ = show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    update_unread(app);
    Ok(())
}
