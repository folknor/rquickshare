//! RQuickShare - egui frontend

use std::sync::mpsc;
use std::thread;

use eframe::egui;
use rqs::channel::{ChannelMessage, Message, TransferAction};
use rqs::hdl::{EndpointInfo, TransferState};
use rqs::{OutboundPayload, SendInfo, RQS};
use tokio::sync::broadcast;

/// Message types for the GUI channel
enum GuiMessage {
    Channel(ChannelMessage),
    Endpoint(EndpointInfo),
}

// Catppuccin Mocha palette
mod theme {
    use eframe::egui::Color32;

    pub const BASE: Color32 = Color32::from_rgb(30, 30, 46);
    pub const SURFACE1: Color32 = Color32::from_rgb(69, 71, 90);
    pub const TEXT: Color32 = Color32::from_rgb(205, 214, 244);
    pub const SUBTEXT0: Color32 = Color32::from_rgb(166, 173, 200);
    pub const OVERLAY0: Color32 = Color32::from_rgb(108, 112, 134);
    pub const BLUE: Color32 = Color32::from_rgb(137, 180, 250);
    pub const GREEN: Color32 = Color32::from_rgb(166, 227, 161);
    pub const RED: Color32 = Color32::from_rgb(243, 139, 168);
    pub const MAUVE: Color32 = Color32::from_rgb(203, 166, 247);
}

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 450.0])
            .with_min_inner_size([300.0, 350.0]),
        ..Default::default()
    };

    eframe::run_native(
        "RQuickShare",
        options,
        Box::new(|cc| {
            catppuccin_egui::set_theme(&cc.egui_ctx, catppuccin_egui::MOCHA);
            Ok(Box::new(RQuickShareApp::new(cc)))
        }),
    )
}

/// Info about a received file for the tooltip
struct ReceivedFile {
    name: String,
    sender: String,
    size: u64,
}

/// State of an outbound transfer (for the overlay)
struct OutboundTransfer {
    id: String,
    device_name: String,
    pin_code: Option<String>,
    state: TransferState,
    total_bytes: u64,
    ack_bytes: u64,
}

/// State of an inbound transfer (for auto-accept and status)
struct InboundTransfer {
    id: String,
    sender: String,
    file_names: Vec<String>,
    total_bytes: u64,
    ack_bytes: u64,
    state: TransferState,
}

struct RQuickShareApp {
    device_name: String,
    rx: mpsc::Receiver<GuiMessage>,
    cmd_tx: Option<broadcast::Sender<ChannelMessage>>,
    send_tx: Option<tokio::sync::mpsc::Sender<SendInfo>>,
    endpoints: Vec<EndpointInfo>,
    received_files: Vec<ReceivedFile>,
    outbound: Option<OutboundTransfer>,
    inbound: Option<InboundTransfer>,
}

impl RQuickShareApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let (init_tx, init_rx) = std::sync::mpsc::channel::<(
            broadcast::Sender<ChannelMessage>,
            tokio::sync::mpsc::Sender<SendInfo>,
            String,
        )>();

        let ctx = cc.egui_ctx.clone();

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async move {
                let mut rqs = RQS::default();
                let device_name = rqs.get_device_name();
                let message_sender = rqs.message_sender.clone();
                let mut receiver = rqs.message_sender.subscribe();

                match rqs.run().await {
                    Ok((sender_file, _ble_receiver)) => {
                        drop(init_tx.send((message_sender, sender_file, device_name)));

                        // Start device discovery
                        let (endpoint_tx, mut endpoint_rx) = broadcast::channel::<EndpointInfo>(50);
                        if let Err(e) = rqs.discovery(endpoint_tx) {
                            log::error!("Failed to start discovery: {e}");
                        }

                        let tx_endpoint = tx.clone();
                        let ctx_endpoint = ctx.clone();
                        tokio::spawn(async move {
                            loop {
                                match endpoint_rx.recv().await {
                                    Ok(endpoint) => {
                                        drop(tx_endpoint.send(GuiMessage::Endpoint(endpoint)));
                                        ctx_endpoint.request_repaint();
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                }
                            }
                        });

                        loop {
                            match receiver.recv().await {
                                Ok(msg) => {
                                    if let Message::Client(_) = &msg.msg {
                                        drop(tx.send(GuiMessage::Channel(msg)));
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

        let (cmd_tx, send_tx, device_name) = init_rx
            .recv()
            .map(|(cmd, send, name)| (Some(cmd), Some(send), name))
            .unwrap_or((None, None, "Unknown".to_string()));

        Self {
            device_name,
            rx,
            cmd_tx,
            send_tx,
            endpoints: Vec::new(),
            received_files: Vec::new(),
            outbound: None,
            inbound: None,
        }
    }

    fn process_messages(&mut self) {
        while let Ok(gui_msg) = self.rx.try_recv() {
            match gui_msg {
                GuiMessage::Channel(msg) => self.handle_channel_message(&msg),
                GuiMessage::Endpoint(endpoint) => self.handle_endpoint(endpoint),
            }
        }
    }

    fn handle_channel_message(&mut self, msg: &ChannelMessage) {
        if let Message::Client(client) = &msg.msg {
            let state = client.state.clone().unwrap_or(TransferState::Initial);
            let is_outbound = client.kind == rqs::channel::TransferKind::Outbound;

            if is_outbound {
                self.handle_outbound_message(&msg.id, &state, client);
            } else {
                self.handle_inbound_message(&msg.id, &state, client);
            }
        }
    }

    fn handle_outbound_message(&mut self, id: &str, state: &TransferState, client: &rqs::channel::MessageClient) {
        if let Some(outbound) = &mut self.outbound {
            if outbound.id == id {
                outbound.state = state.clone();
                if let Some(meta) = &client.metadata {
                    outbound.total_bytes = meta.total_bytes;
                    outbound.ack_bytes = meta.ack_bytes;
                    if outbound.pin_code.is_none() {
                        outbound.pin_code = meta.pin_code.clone();
                    }
                }
            }
        } else if let Some(meta) = &client.metadata {
            // New outbound transfer
            self.outbound = Some(OutboundTransfer {
                id: id.to_string(),
                device_name: meta.source.as_ref().map_or("Unknown".to_string(), |s| s.name.clone()),
                pin_code: meta.pin_code.clone(),
                state: state.clone(),
                total_bytes: meta.total_bytes,
                ack_bytes: meta.ack_bytes,
            });
        }
    }

    fn handle_inbound_message(&mut self, id: &str, state: &TransferState, client: &rqs::channel::MessageClient) {
        // Auto-accept incoming transfers
        if *state == TransferState::WaitingForUserConsent {
            self.send_action(id, TransferAction::ConsentAccept);
        }

        if let Some(inbound) = &mut self.inbound {
            if inbound.id == id {
                inbound.state = state.clone();
                if let Some(meta) = &client.metadata {
                    inbound.total_bytes = meta.total_bytes;
                    inbound.ack_bytes = meta.ack_bytes;
                }

                // Transfer finished - add to received files
                if *state == TransferState::Finished {
                    for name in &inbound.file_names {
                        self.received_files.push(ReceivedFile {
                            name: name.clone(),
                            sender: inbound.sender.clone(),
                            size: inbound.total_bytes,
                        });
                    }
                    self.inbound = None;
                } else if matches!(state, TransferState::Cancelled | TransferState::Rejected | TransferState::Disconnected) {
                    self.inbound = None;
                }
            }
        } else if let Some(meta) = &client.metadata {
            // New inbound transfer
            let file_names = meta.payload.as_ref().map_or_else(Vec::new, |p| {
                match p {
                    rqs::hdl::info::TransferPayload::Files(files) => files.clone(),
                    rqs::hdl::info::TransferPayload::Text(t) => vec![format!("Text: {}", t.chars().take(50).collect::<String>())],
                    rqs::hdl::info::TransferPayload::Url(u) => vec![format!("URL: {u}")],
                    rqs::hdl::info::TransferPayload::Wifi { ssid, .. } => vec![format!("WiFi: {ssid}")],
                }
            });

            self.inbound = Some(InboundTransfer {
                id: id.to_string(),
                sender: meta.source.as_ref().map_or("Unknown".to_string(), |s| s.name.clone()),
                file_names,
                total_bytes: meta.total_bytes,
                ack_bytes: meta.ack_bytes,
                state: state.clone(),
            });
        }
    }

    fn handle_endpoint(&mut self, endpoint: EndpointInfo) {
        if endpoint.name.is_none() || endpoint.present == Some(false) {
            self.endpoints.retain(|e| e.id != endpoint.id);
        } else if let Some(existing) = self.endpoints.iter_mut().find(|e| e.id == endpoint.id) {
            *existing = endpoint;
        } else {
            self.endpoints.push(endpoint);
        }
    }

    fn send_action(&self, id: &str, action: TransferAction) {
        if let Some(cmd_tx) = &self.cmd_tx {
            let msg = ChannelMessage {
                id: id.to_string(),
                msg: Message::Lib { action },
            };
            drop(cmd_tx.send(msg));
        }
    }

    fn send_files_to(&self, endpoint: &EndpointInfo, files: Vec<String>) {
        if let (Some(send_tx), Some(ip), Some(port)) = (&self.send_tx, &endpoint.ip, &endpoint.port) {
            let info = SendInfo {
                id: endpoint.id.clone(),
                name: endpoint.name.clone().unwrap_or_else(|| "Unknown".to_string()),
                addr: format!("{ip}:{port}"),
                ob: OutboundPayload::Files(files),
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

    fn draw_device_circle(&self, ui: &mut egui::Ui, endpoint: &EndpointInfo) -> bool {
        let name = endpoint.name.as_deref().unwrap_or("Unknown");
        let mut clicked = false;

        ui.vertical(|ui| {
            ui.set_width(80.0);

            let (rect, response) = ui.allocate_exact_size(egui::vec2(60.0, 60.0), egui::Sense::click());

            if response.clicked() {
                clicked = true;
            }

            let color = if response.hovered() { theme::BLUE } else { theme::SURFACE1 };
            ui.painter().circle_filled(rect.center(), 30.0, color);

            // First letter of name
            let initial = name.chars().next().unwrap_or('?').to_uppercase().to_string();
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                initial,
                egui::FontId::proportional(24.0),
                theme::TEXT,
            );

            ui.add_space(4.0);
            ui.label(egui::RichText::new(name).size(12.0).color(theme::TEXT));
        });

        clicked
    }
}

impl eframe::App for RQuickShareApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_messages();

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::BASE).inner_margin(egui::Margin::same(16)))
            .show(ctx, |ui| {
                // Header: device name
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new(&self.device_name)
                        .size(18.0)
                        .strong()
                        .color(theme::TEXT));
                });
                ui.add_space(20.0);

                // Main content area
                let available_height = ui.available_height() - 40.0; // Reserve space for footer

                egui::Frame::new()
                    .fill(theme::BASE)
                    .show(ui, |ui| {
                        ui.set_min_height(available_height);

                        // Check if we have an active outbound transfer (overlay)
                        if self.outbound.is_some() {
                            self.draw_send_overlay(ui);
                        } else {
                            self.draw_device_grid(ui);
                        }
                    });

                // Footer: received files count
                ui.add_space(8.0);
                self.draw_footer(ui);
            });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

impl RQuickShareApp {
    fn draw_device_grid(&mut self, ui: &mut egui::Ui) {
        if self.endpoints.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(egui::RichText::new("Searching for nearby devices...")
                    .size(14.0)
                    .color(theme::OVERLAY0));
            });
            return;
        }

        ui.vertical_centered(|ui| {
            ui.add_space(20.0);

            // Create a grid of device circles
            let endpoints_snapshot: Vec<_> = self.endpoints.clone();
            let mut clicked_endpoint: Option<EndpointInfo> = None;

            egui::Grid::new("device_grid")
                .spacing([20.0, 20.0])
                .show(ui, |ui| {
                    for (i, endpoint) in endpoints_snapshot.iter().enumerate() {
                        if self.draw_device_circle(ui, endpoint) {
                            clicked_endpoint = Some(endpoint.clone());
                        }
                        if (i + 1) % 3 == 0 {
                            ui.end_row();
                        }
                    }
                });

            // Handle click - open file picker
            if let Some(endpoint) = clicked_endpoint
                && let Some(paths) = rfd::FileDialog::new().pick_files()
            {
                let files: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
                if !files.is_empty() {
                    self.send_files_to(&endpoint, files);
                }
            }
        });
    }

    #[allow(clippy::cast_precision_loss)]
    fn draw_send_overlay(&mut self, ui: &mut egui::Ui) {
        let Some(outbound) = &self.outbound else { return };

        let is_done = matches!(
            outbound.state,
            TransferState::Finished | TransferState::Cancelled | TransferState::Rejected | TransferState::Disconnected
        );
        let device_name = outbound.device_name.clone();
        let pin_code = outbound.pin_code.clone();
        let progress = if outbound.total_bytes > 0 {
            outbound.ack_bytes as f32 / outbound.total_bytes as f32
        } else {
            0.0
        };
        let state = outbound.state.clone();

        let mut close_clicked = false;

        ui.vertical_centered(|ui| {
            ui.add_space(40.0);

            // Device name
            ui.label(egui::RichText::new(format!("Sending to {device_name}"))
                .size(16.0)
                .color(theme::TEXT));
            ui.add_space(20.0);

            // PIN code
            if let Some(pin) = &pin_code {
                ui.label(egui::RichText::new("PIN").size(12.0).color(theme::SUBTEXT0));
                ui.label(egui::RichText::new(pin)
                    .size(32.0)
                    .strong()
                    .color(theme::MAUVE));
                ui.add_space(20.0);
            }

            // Progress bar
            ui.add(egui::ProgressBar::new(progress)
                .show_percentage()
                .fill(theme::BLUE));
            ui.add_space(20.0);

            // Status
            let (status_text, status_color) = match &state {
                TransferState::Finished => ("Transfer complete!", theme::GREEN),
                TransferState::Cancelled => ("Cancelled", theme::OVERLAY0),
                TransferState::Rejected => ("Rejected by receiver", theme::RED),
                TransferState::Disconnected => ("Disconnected", theme::RED),
                TransferState::SendingFiles => ("Sending...", theme::BLUE),
                _ => ("Connecting...", theme::OVERLAY0),
            };
            ui.label(egui::RichText::new(status_text).size(14.0).color(status_color));

            // Close button (only when done)
            if is_done {
                ui.add_space(20.0);
                if ui.add(egui::Button::new(
                    egui::RichText::new("Close").color(theme::TEXT))
                    .fill(theme::SURFACE1)
                    .min_size(egui::vec2(100.0, 36.0))
                ).clicked() {
                    close_clicked = true;
                }
            }
        });

        if close_clicked {
            self.outbound = None;
        }
    }

    fn draw_footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Downloading indicator
            if let Some(inbound) = &self.inbound
                && matches!(inbound.state, TransferState::ReceivingFiles)
            {
                ui.label(egui::RichText::new("Downloading...")
                    .size(13.0)
                    .color(theme::BLUE));
                return;
            }

            // Received files count
            let count = self.received_files.len();
            let label_text = if count == 0 {
                "No files received".to_string()
            } else if count == 1 {
                "1 file received".to_string()
            } else {
                format!("{count} files received")
            };

            let response = ui.label(egui::RichText::new(&label_text)
                .size(13.0)
                .color(theme::SUBTEXT0));

            // Tooltip on hover
            if count > 0 {
                response.on_hover_ui(|ui| {
                    for file in &self.received_files {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&file.name).color(theme::TEXT));
                            ui.label(egui::RichText::new(format!("from {}", file.sender))
                                .size(11.0)
                                .color(theme::SUBTEXT0));
                            ui.label(egui::RichText::new(format_size(file.size))
                                .size(11.0)
                                .color(theme::OVERLAY0));
                        });
                    }
                });
            }
        });
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
