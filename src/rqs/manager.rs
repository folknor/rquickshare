use std::sync::LazyLock;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;


use crate::channel::{self, ChannelMessage, MessageClient, TransferKind};
use crate::errors::AppError;
use crate::hdl::{InboundRequest, OutboundPayload, OutboundRequest, TransferState};
use crate::utils::RemoteDeviceInfo;

const INNER_NAME: &str = "TcpServer";

/// Maximum concurrent connections to prevent DoS/resource exhaustion
const MAX_CONCURRENT_CONNECTIONS: usize = 100;

/// Global semaphore for connection rate limiting
static CONNECTION_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendInfo {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub ob: OutboundPayload,
}

pub struct TcpServer {
    endpoint_id: [u8; 4],
    tcp_listener: TcpListener,
    sender: Sender<ChannelMessage>,
    connect_receiver: Receiver<SendInfo>,
}

impl TcpServer {
    pub fn new(
        endpoint_id: [u8; 4],
        tcp_listener: TcpListener,
        sender: Sender<ChannelMessage>,
        connect_receiver: Receiver<SendInfo>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            endpoint_id,
            tcp_listener,
            sender,
            connect_receiver,
        })
    }

    pub async fn run(&mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");

        loop {
            let cctk = ctk.clone();

            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                Some(i) = self.connect_receiver.recv() => {
                    info!("{INNER_NAME}: connect_receiver: got {i:?}");
                    if let Err(e) = self.connect(cctk, i).await {
                        error!("{INNER_NAME}: error sending: {e}");
                    }
                }
                r = self.tcp_listener.accept() => {
                    match r {
                        Ok((socket, remote_addr)) => {
                            trace!("{INNER_NAME}: new client: {remote_addr}");

                            // Set TCP socket options for better performance
                            if let Err(e) = socket.set_nodelay(true) {
                                warn!("{INNER_NAME}: failed to set TCP_NODELAY: {e}");
                            }

                            // Try to acquire connection permit (non-blocking)
                            let permit = match CONNECTION_SEMAPHORE.try_acquire() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!("{INNER_NAME}: connection limit reached, rejecting {remote_addr}");
                                    drop(socket);
                                    continue;
                                }
                            };

                            let esender = self.sender.clone();
                            let csender = self.sender.clone();

                            tokio::spawn(async move {
                                // Permit is moved into the task and released when dropped
                                let _permit = permit;
                                let mut ir = InboundRequest::new(socket, remote_addr.to_string(), csender);

                                loop {
                                    match ir.handle().await {
                                        Ok(_) => {},
                                        Err(e) => match e.downcast_ref() {
                                            Some(AppError::NotAnError) => break,
                                            None => {
                                                if ir.state.state == TransferState::Initial {
                                                    break;
                                                }

                                                if ir.state.state != TransferState::Finished {
                                                    drop(esender.send(ChannelMessage {
                                                        id: remote_addr.to_string(),
                                                        msg: channel::Message::Client(MessageClient {
                                                            kind: TransferKind::Inbound,
                                                            state: Some(TransferState::Disconnected),
                                                            metadata: Default::default()
                                                        }),
                                                    }));
                                                    error!("{INNER_NAME}: error while handling client: {e} ({:?})", ir.state.state);
                                                } else {
                                                    debug!("{INNER_NAME}: connection closed after transfer complete");
                                                }
                                                break;
                                            }
                                        },
                                    }
                                }
                            });
                        },
                        Err(err) => {
                            error!("{INNER_NAME}: error accepting: {err}");
                            // Don't break on transient errors (e.g. EMFILE, ENOMEM)
                            // - only a cancelled token should stop the server
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// To be called inside a separate task if we want to handle concurrency
    pub async fn connect(&self, ctk: CancellationToken, si: SendInfo) -> Result<(), anyhow::Error> {
        debug!("{INNER_NAME}: Connecting to: {}", si.addr);
        let socket = TcpStream::connect(si.addr.clone()).await?;

        // Set TCP socket options for better performance
        if let Err(e) = socket.set_nodelay(true) {
            warn!("{INNER_NAME}: failed to set TCP_NODELAY: {e}");
        }

        let mut or = OutboundRequest::new(
            self.endpoint_id,
            socket,
            si.id,
            self.sender.clone(),
            si.ob,
            RemoteDeviceInfo {
                device_type: crate::DeviceType::Unknown,
                name: si.name,
            },
        );

        // Send connection request
        or.send_connection_request().await?;
        // Send UKEY init
        or.send_ukey2_client_init().await?;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                },
                r = or.handle() => {
                    if let Err(e) = r {
                        match e.downcast_ref() {
                            Some(AppError::NotAnError) => break,
                            None => {
                                if or.state.state == TransferState::Initial {
                                    break;
                                }

                                if or.state.state == TransferState::Finished || or.state.state == TransferState::Cancelled {
                                    // Connection closed after transfer completed - this is normal
                                    debug!("{INNER_NAME}: connection closed after transfer ({:?})", or.state.state);
                                } else {
                                    drop(self.sender.clone().send(ChannelMessage {
                                        id: si.addr,
                                        msg: channel::Message::Client(MessageClient {
                                            kind: TransferKind::Outbound,
                                            state: Some(TransferState::Disconnected),
                                            metadata: Default::default()
                                        }),
                                    }));
                                    error!("{INNER_NAME}: error while handling client: {e} ({:?})", or.state.state);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
