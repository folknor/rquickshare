#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

#[macro_use]
extern crate log;

use std::sync::OnceLock;

use rqs::channel::{ChannelMessage, Message};
use rqs::{EndpointInfo, SendInfo, Visibility, RQS};
use tauri::{AppHandle, Emitter, Manager, Window, WindowEvent};
use tokio::sync::{broadcast, mpsc};

mod cmds;

pub struct AppState {
    pub message_sender: broadcast::Sender<ChannelMessage>,
    pub dch_sender: broadcast::Sender<EndpointInfo>,
    /// Populated after RQS::run() completes
    pub sender_file: OnceLock<mpsc::Sender<SendInfo>>,
    pub rqs: tokio::sync::Mutex<RQS>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Initialize stdout logging
    env_logger::init();

    // Define tauri async runtime to be tokio
    tauri::async_runtime::set(tokio::runtime::Handle::current());

    // Build and run Tauri app
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            trace!("tauri_plugin_single_instance: instance already running");
            open_main_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            cmds::is_ready,
            cmds::start_discovery,
            cmds::stop_discovery,
            cmds::get_hostname,
            cmds::send_payload,
            cmds::send_to_rs,
        ])
        .setup(|app| {
            debug!("Starting setup of RQuickShare app");

            // Create RQS instance - always visible, use default download path
            trace!("Creating RQS instance");
            let rqs = RQS::new(Visibility::Visible, None, None, None);

            // Define state for tauri app immediately (window can show now!)
            app.app_handle().manage(AppState {
                message_sender: rqs.message_sender.clone(),
                dch_sender: broadcast::channel(10).0,
                sender_file: OnceLock::new(),
                rqs: tokio::sync::Mutex::new(rqs),
            });

            // Spawn message receiver tasks
            spawn_receiver_tasks(app.app_handle());

            // Spawn RQS initialization in background - window shows immediately
            let app_handle = app.app_handle().clone();
            tauri::async_runtime::spawn(async move {
                trace!("Beginning of RQS start (background)");
                let state: tauri::State<'_, AppState> = app_handle.state();

                // Run RQS (this is the slow part - TCP, BLE, mDNS init)
                let run_result = {
                    let mut rqs = state.rqs.lock().await;
                    rqs.run().await
                };

                match run_result {
                    Ok((sender_file, _ble_receiver)) => {
                        // Store sender_file for later use
                        drop(state.sender_file.set(sender_file));
                        trace!("RQS started successfully");

                        // Emit event to frontend that backend is ready
                        drop(app_handle.emit("backend_ready", ()));
                    }
                    Err(e) => {
                        error!("Failed to start RQS: {e}");
                        drop(app_handle.emit("backend_error", e.to_string()));
                    }
                }
            });
            Ok(())
        })
        .on_window_event(handle_window_event)
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::ExitRequested { code, .. } => {
                trace!("RunEvent::ExitRequested");
                if code != Some(-1) {
                    kill_app(app_handle);
                }
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => {
                trace!("RunEvent::Reopen");
                open_main_window(app_handle);
            }
            _ => {}
        });

    info!("Application stopped");
    Ok(())
}

fn spawn_receiver_tasks(app_handle: &AppHandle) {
    let capp_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        let state: tauri::State<'_, AppState> = capp_handle.state();
        let mut receiver = state.message_sender.subscribe();

        loop {
            let rinfo = receiver.recv().await;

            match rinfo {
                Ok(ref info) => {
                    rs2js_channelmessage(info, &capp_handle);
                }
                Err(e) => {
                    error!("RecvError: message_sender: {e}");
                }
            }
        }
    });

    let capp_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        let state: tauri::State<'_, AppState> = capp_handle.state();
        let mut dch_receiver = state.dch_sender.subscribe();

        loop {
            let rinfo = dch_receiver.recv().await;

            match rinfo {
                Ok(ref info) => rs2js_endpointinfo(info, &capp_handle),
                Err(e) => {
                    error!("RecvError: dch_sender: {e}");
                }
            }
        }
    });
}

fn handle_window_event(w: &Window, event: &WindowEvent) {
    if let tauri::WindowEvent::CloseRequested { .. } = event {
        trace!("handle_window_event: close requested");
        kill_app(w.app_handle());
    }
}

fn rs2js_channelmessage(message: &ChannelMessage, manager: &AppHandle) {
    // Only forward client messages to the frontend
    if matches!(message.msg, Message::Lib { .. }) {
        return;
    }

    info!("rs2js_channelmessage: {message:?}");
    manager.emit("rs2js_channelmessage", message).unwrap();
}

fn rs2js_endpointinfo(message: &EndpointInfo, manager: &AppHandle) {
    info!("rs2js_endpointinfo: {message:?}");
    manager.emit("rs2js_endpointinfo", message).unwrap();
}

fn open_main_window(app_handle: &AppHandle) {
    if let Some(webview_window) = app_handle.get_webview_window("main") {
        drop(webview_window.show());
        drop(webview_window.set_focus());
        return;
    }

    warn!("open_main_window: no main window found");
}

fn kill_app(app_handle: &AppHandle) {
    let state: tauri::State<'_, AppState> = app_handle.state();

    tokio::task::block_in_place(|| {
        tauri::async_runtime::block_on(async move {
            let _ = state.rqs.lock().await.stop().await;
        });
    });

    app_handle.exit(0);
}
