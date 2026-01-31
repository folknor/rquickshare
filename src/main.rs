//! RQuickShare - egui frontend

use std::sync::mpsc;
use std::thread;

use eframe::egui;
use rqs::channel::{ChannelMessage, Message, TransferAction};
use rqs::hdl::{EndpointInfo, TransferState};
use rqs::{OutboundPayload, SendInfo, RQS};
use tokio::sync::broadcast;

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 500.0])
            .with_min_inner_size([300.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "RQuickShare",
        options,
        Box::new(|cc| Ok(Box::new(RQuickShareApp::new(cc)))),
    )
}

struct Transfer {
    id: String,
    device_name: String,
    file_names: Vec<String>,
    pin_code: Option<String>,
    state: TransferState,
    total_bytes: u64,
    ack_bytes: u64,
}

struct RQuickShareApp {
    // Channel to receive messages from RQS backend
    rx: mpsc::Receiver<ChannelMessage>,
    // Channel to send commands to RQS backend
    cmd_tx: Option<broadcast::Sender<ChannelMessage>>,
    // Channel to send files
    send_tx: Option<tokio::sync::mpsc::Sender<SendInfo>>,

    // UI state
    transfers: Vec<Transfer>,
    endpoints: Vec<EndpointInfo>,
    outbound_files: Vec<String>,
    status_message: String,
}

impl RQuickShareApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Channels for communicating between tokio runtime and egui
        let (tx, rx) = mpsc::channel();
        let (init_tx, init_rx) = std::sync::mpsc::channel::<(
            broadcast::Sender<ChannelMessage>,
            tokio::sync::mpsc::Sender<SendInfo>,
        )>();

        let ctx = cc.egui_ctx.clone();

        // Spawn tokio runtime in background thread
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async move {
                let mut rqs = RQS::default();
                let message_sender = rqs.message_sender.clone();
                let mut receiver = rqs.message_sender.subscribe();

                // Start RQS
                match rqs.run().await {
                    Ok((sender_file, _ble_receiver)) => {
                        // Send initialization data back to the main thread
                        drop(init_tx.send((message_sender, sender_file)));

                        // Forward messages to UI
                        loop {
                            match receiver.recv().await {
                                Ok(msg) => {
                                    if let Message::Client(_) = &msg.msg {
                                        drop(tx.send(msg));
                                        ctx.request_repaint();
                                    }
                                }
                                Err(e) => {
                                    log::error!("Receiver error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to start RQS: {e}");
                    }
                }
            });
        });

        // Get the channels (blocking wait, but should be fast)
        let (cmd_tx, send_tx) = init_rx
            .recv()
            .map(|(cmd, send)| (Some(cmd), Some(send)))
            .unwrap_or((None, None));

        Self {
            rx,
            cmd_tx,
            send_tx,
            transfers: Vec::new(),
            endpoints: Vec::new(),
            outbound_files: Vec::new(),
            status_message: String::from("Ready"),
        }
    }

    fn process_messages(&mut self) {
        // Process all pending messages
        while let Ok(msg) = self.rx.try_recv() {
            if let Message::Client(client) = &msg.msg {
                let state = client.state.clone().unwrap_or(TransferState::Initial);

                // Find existing transfer or create new one
                if let Some(transfer) = self.transfers.iter_mut().find(|t| t.id == msg.id) {
                    transfer.state = state.clone();
                    if let Some(meta) = &client.metadata {
                        transfer.total_bytes = meta.total_bytes;
                        transfer.ack_bytes = meta.ack_bytes;
                    }
                    // Update state for finished transfers
                    if matches!(state, TransferState::Finished | TransferState::Cancelled | TransferState::Rejected) {
                        transfer.state = state;
                    }
                } else if let Some(meta) = &client.metadata {
                    let file_names = meta.payload.as_ref().map_or_else(Vec::new, |p| {
                        match p {
                            rqs::hdl::info::TransferPayload::Files(files) => files.clone(),
                            rqs::hdl::info::TransferPayload::Text(t) => vec![format!("Text: {}", t.chars().take(50).collect::<String>())],
                            rqs::hdl::info::TransferPayload::Url(u) => vec![format!("URL: {u}")],
                            rqs::hdl::info::TransferPayload::Wifi { ssid, .. } => vec![format!("WiFi: {ssid}")],
                        }
                    });

                    self.transfers.push(Transfer {
                        id: msg.id.clone(),
                        device_name: meta.source.as_ref().map_or_else(|| "Unknown".to_string(), |s| s.name.clone()),
                        file_names,
                        pin_code: meta.pin_code.clone(),
                        state,
                        total_bytes: meta.total_bytes,
                        ack_bytes: meta.ack_bytes,
                    });
                }
            }
        }

        // Clean up disconnected transfers
        self.transfers.retain(|t| {
            !matches!(t.state, TransferState::Disconnected)
        });
    }

    fn send_action(&self, id: &str, action: TransferAction) {
        if let Some(cmd_tx) = &self.cmd_tx {
            let msg = ChannelMessage {
                id: id.to_string(),
                msg: Message::Lib { action },
            };
            if let Err(e) = cmd_tx.send(msg) {
                log::error!("Failed to send action: {e}");
            }
        }
    }

    fn clear_transfer(&mut self, id: &str) {
        self.transfers.retain(|t| t.id != id);
    }

    fn draw_transfers_section(&mut self, ui: &mut egui::Ui) {
        if self.transfers.is_empty() {
            return;
        }

        ui.heading("Transfers");
        ui.separator();

        let transfers_snapshot: Vec<_> = self.transfers.iter().map(|t| {
            (t.id.clone(), t.device_name.clone(), t.file_names.clone(),
             t.pin_code.clone(), t.state.clone(), t.total_bytes, t.ack_bytes)
        }).collect();

        let mut to_clear = Vec::new();

        for (id, device_name, file_names, pin_code, state, total_bytes, ack_bytes) in transfers_snapshot {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(&device_name);
                    if let Some(pin) = &pin_code {
                        ui.label(format!("PIN: {pin}"));
                    }
                });

                for file in &file_names {
                    ui.label(format!("  {file}"));
                }

                self.draw_transfer_state(ui, &id, &state, total_bytes, ack_bytes, &mut to_clear);
            });
            ui.add_space(8.0);
        }

        for id in to_clear {
            self.clear_transfer(&id);
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn draw_transfer_state(&self, ui: &mut egui::Ui, id: &str, state: &TransferState,
                           total_bytes: u64, ack_bytes: u64, to_clear: &mut Vec<String>) {
        match state {
            TransferState::WaitingForUserConsent => {
                ui.horizontal(|ui| {
                    if ui.button("Accept").clicked() {
                        self.send_action(id, TransferAction::ConsentAccept);
                    }
                    if ui.button("Decline").clicked() {
                        self.send_action(id, TransferAction::ConsentDecline);
                    }
                });
            }
            TransferState::ReceivingFiles | TransferState::SendingFiles => {
                let progress = if total_bytes > 0 {
                    ack_bytes as f32 / total_bytes as f32
                } else {
                    0.0
                };
                ui.add(egui::ProgressBar::new(progress).show_percentage());
                if ui.button("Cancel").clicked() {
                    self.send_action(id, TransferAction::TransferCancel);
                }
            }
            TransferState::Finished => {
                ui.colored_label(egui::Color32::GREEN, "Transfer complete!");
                if ui.button("Clear").clicked() {
                    to_clear.push(id.to_string());
                }
            }
            TransferState::Cancelled => {
                ui.colored_label(egui::Color32::YELLOW, "Cancelled");
                if ui.button("Clear").clicked() {
                    to_clear.push(id.to_string());
                }
            }
            TransferState::Rejected => {
                ui.colored_label(egui::Color32::RED, "Rejected");
                if ui.button("Clear").clicked() {
                    to_clear.push(id.to_string());
                }
            }
            _ => {
                ui.label(format!("State: {state:?}"));
            }
        }
    }

    fn draw_send_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("Send Files");
        ui.separator();

        if ui.button("Select Files...").clicked()
            && let Some(paths) = rfd::FileDialog::new().pick_files()
        {
            self.outbound_files = paths.iter().map(|p| p.display().to_string()).collect();
            self.status_message = format!("Selected {} file(s)", self.outbound_files.len());
        }

        if self.outbound_files.is_empty() {
            return;
        }

        ui.label("Selected files:");
        for file in &self.outbound_files {
            ui.label(format!("  {file}"));
        }

        if !self.endpoints.is_empty() {
            self.draw_endpoint_buttons(ui);
        } else {
            ui.label("(Discovery not yet implemented in egui version)");
        }

        if ui.button("Clear Selection").clicked() {
            self.outbound_files.clear();
            self.status_message = String::from("Ready");
        }
    }

    fn draw_endpoint_buttons(&self, ui: &mut egui::Ui) {
        ui.label("Send to:");
        for endpoint in &self.endpoints {
            if ui.button(endpoint.name.as_deref().unwrap_or("Unknown")).clicked()
                && let (Some(send_tx), Some(ip), Some(port)) = (&self.send_tx, &endpoint.ip, &endpoint.port)
            {
                let info = SendInfo {
                    id: endpoint.id.clone(),
                    name: endpoint.name.clone().unwrap_or_else(|| "Unknown".to_string()),
                    addr: format!("{ip}:{port}"),
                    ob: OutboundPayload::Files(self.outbound_files.clone()),
                };
                let tx = send_tx.clone();
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Runtime::new() {
                        rt.block_on(async {
                            drop(tx.send(info).await);
                        });
                    }
                });
            }
        }
    }
}

impl eframe::App for RQuickShareApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_messages();

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("RQuickShare");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(&self.status_message);
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.draw_transfers_section(ui);
            ui.add_space(16.0);
            self.draw_send_section(ui);
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
