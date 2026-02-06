use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use hmac::{Hmac, Mac};
use libaes::{AES_256_KEY_LEN, Cipher};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::broadcast::{Receiver, Sender};

use super::info::{InternalFileInfo, TransferMetadata, TransferPayload, TransferPayloadKind};
use super::{InnerState, TransferState};
use crate::channel::{self, ChannelMessage, MessageClient, TransferAction, TransferKind};
use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;
use crate::location_nearby_connections::connection_response_frame::ResponseStatus;
use crate::location_nearby_connections::payload_transfer_frame::{
    PacketType, PayloadChunk, PayloadHeader, payload_header,
};
use crate::location_nearby_connections::{KeepAliveFrame, OfflineFrame, PayloadTransferFrame};
use crate::securegcm::ukey2_alert::AlertType;
use crate::securegcm::ukey2_client_init::CipherCommitment;
use crate::securegcm::{
    DeviceToDeviceMessage, GcmMetadata, Type, Ukey2Alert, Ukey2ClientFinished, Ukey2ClientInit,
    Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit, ukey2_message,
};
use crate::securemessage::{
    EcP256PublicKey, EncScheme, GenericPublicKey, Header, HeaderAndBody, PublicKeyType,
    SecureMessage, SigScheme,
};
use crate::sharing_nearby::{
    FileMetadata, IntroductionFrame, file_metadata, paired_key_result_frame,
};
use crate::utils::{
    DeviceType, RemoteDeviceInfo, encode_point, gen_ecdsa_keypair, gen_random, hkdf_extract_expand,
    stream_read_exact, to_four_digit_string,
};
use crate::{DEVICE_NAME, location_nearby_connections, sharing_nearby};

type HmacSha256 = Hmac<Sha256>;

const SANE_FRAME_LENGTH: i32 = 5 * 1024 * 1024;
const SANITY_DURATION: Duration = Duration::from_micros(10);

/// Timeout for waiting for PAYLOAD_RECEIVED_ACK (Google uses 30 seconds)
const ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Additional timeout for waiting for ack_safe_to_disconnect after ACKs received (Google uses 10 seconds)
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OutboundPayload {
    Files(Vec<String>),
}

#[derive(Debug)]
pub struct OutboundRequest {
    endpoint_id: [u8; 4],
    socket: TcpStream,
    pub state: InnerState,
    sender: Sender<ChannelMessage>,
    receiver: Receiver<ChannelMessage>,
    payload: OutboundPayload,
}

impl OutboundRequest {
    pub fn new(
        endpoint_id: [u8; 4],
        socket: TcpStream,
        id: String,
        sender: Sender<ChannelMessage>,
        payload: OutboundPayload,
        rdi: RemoteDeviceInfo,
    ) -> Self {
        let receiver = sender.subscribe();
        let OutboundPayload::Files(files) = &payload;

        Self {
            endpoint_id,
            socket,
            state: InnerState::new(
                id,
                Some(TransferMetadata {
                    source: Some(rdi),
                    payload_kind: TransferPayloadKind::Files,
                    payload: Some(TransferPayload::Files(files.clone())),
                    id: String::new(),
                    pin_code: None,
                    payload_preview: None,
                    total_bytes: 0,
                    ack_bytes: 0,
                }),
            ),
            sender,
            receiver,
            payload,
        }
    }

    pub async fn handle(&mut self) -> Result<(), anyhow::Error> {
        // Check for timeout based on current state
        if let Some(started) = self.state.ack_wait_started {
            let timeout = match self.state.state {
                TransferState::WaitingForPayloadAck => ACK_TIMEOUT,
                TransferState::WaitingForDisconnectAck => DISCONNECT_TIMEOUT,
                _ => ACK_TIMEOUT,
            };
            if started.elapsed() > timeout {
                info!("Timeout reached in state {:?}, finishing transfer", self.state.state);
                self.update_state(|e| { e.state = TransferState::Finished; }, true).await;
                return Err(anyhow!(crate::errors::AppError::NotAnError));
            }
        }

        // Buffer for the 4-byte length
        let mut length_buf = [0u8; 4];

        // Use a shorter timeout when waiting for ACKs/disconnect to allow periodic timeout checks
        let read_timeout = if self.state.ack_wait_started.is_some() {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(30)
        };

        tokio::select! {
            i = self.receiver.recv() => {
                match i {
                    Ok(channel_msg) => {
                        if channel_msg.id != self.state.id {
                            return Ok(());
                        }

                        if let channel::Message::Lib { action }  = &channel_msg.msg {
                            debug!("outbound: got: {channel_msg:?}");
                            if action == &TransferAction::TransferCancel {
                                self.update_state(
                                    |e| {
                                        e.state = TransferState::Cancelled;
                                    },
                                    true,
                                ).await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            }
                        }
                    }
                    Err(e) => {
                        error!("inbound: channel error: {e}");
                    }
                }
            },
            result = tokio::time::timeout(read_timeout, stream_read_exact(&mut self.socket, &mut length_buf)) => {
                match result {
                    Ok(h) => {
                        h?;
                        self._handle(length_buf).await?;
                    }
                    Err(_) => {
                        // Timeout - if we're waiting for ACKs, this is expected
                        // Just return Ok to let the loop continue and check timeout
                        if self.state.ack_wait_started.is_some() {
                            return Ok(());
                        }
                        // Otherwise, this is a real timeout error
                        return Err(anyhow!("Read timeout"));
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn _handle(&mut self, length_buf: [u8; 4]) -> Result<(), anyhow::Error> {
        let msg_length = u32::from_be_bytes(length_buf) as usize;
        // Ensure the message length is not unreasonably big to avoid allocation attacks
        if msg_length > SANE_FRAME_LENGTH as usize {
            error!("Message length too big");
            return Err(anyhow!("value"));
        }

        // Allocate buffer for the actual message and read it
        let mut frame_data = vec![0u8; msg_length];
        stream_read_exact(&mut self.socket, &mut frame_data).await?;

        let current_state = &self.state;
        // Now determine what will be the request type based on current state
        match current_state.state {
            TransferState::SentUkeyClientInit => {
                debug!("Handling State::SentUkeyClientInit frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.update_state(
                    |e| {
                        e.server_init_data = Some(frame_data);
                    },
                    false,
                )
                .await;
                self.process_ukey2_server_init(&msg).await?;

                // Advance current state
                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::SentUkeyClientFinish;
                        e.encryption_done = true;
                    },
                    false,
                )
                .await;
            }
            TransferState::SentUkeyClientFinish => {
                debug!("Handling State::SentUkeyClientFinish frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                self.process_connection_response(&frame).await?;

                // Advance current state
                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::SentPairedKeyEncryption;
                        e.server_init_data = Some(frame_data);
                        e.encryption_done = true;
                    },
                    false,
                )
                .await;
            }
            _ => {
                debug!("Handling SecureMessage frame");
                let smsg = SecureMessage::decode(&*frame_data)?;
                self.decrypt_and_process_secure_message(&smsg).await?;
            }
        }

        Ok(())
    }

    pub async fn send_connection_request(&mut self) -> Result<(), anyhow::Error> {
        let device_name = DEVICE_NAME.read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "Unknown".to_string());
        let request = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::ConnectionRequest.into(),
                ),
                connection_request: Some(location_nearby_connections::ConnectionRequestFrame {
                    endpoint_id: Some(String::from_utf8_lossy(&self.endpoint_id).to_string()),
                    endpoint_name: Some(device_name.clone().into()),
                    endpoint_info: Some(
                        RemoteDeviceInfo {
                            name: device_name.clone(),
                            device_type: DeviceType::Laptop,
                        }
                        .serialize(),
                    ),
                    mediums: vec![Medium::WifiLan.into()],
                    // Nonce for simultaneous connection tiebreaking
                    nonce: Some(rand::rng().random()),
                    // Keepalive configuration (10 second interval, 30 second timeout)
                    keep_alive_interval_millis: Some(10_000),
                    keep_alive_timeout_millis: Some(30_000),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        self.send_frame(request.encode_to_vec()).await?;

        Ok(())
    }

    pub async fn send_ukey2_client_init(&mut self) -> Result<(), anyhow::Error> {
        let (secret_key, public_key) = gen_ecdsa_keypair();

        let encoded_point = public_key.to_encoded_point(false);
        let x = encoded_point.x().ok_or_else(|| anyhow!("Missing x coordinate"))?;
        let y = encoded_point.y().ok_or_else(|| anyhow!("Missing y coordinate"))?;

        let pkey = GenericPublicKey {
            r#type: PublicKeyType::EcP256.into(),
            ec_p256_public_key: Some(EcP256PublicKey {
                x: encode_point(x)?,
                y: encode_point(y)?,
            }),
            ..Default::default()
        };

        let finish_frame = Ukey2Message {
            message_type: Some(ukey2_message::Type::ClientFinish.into()),
            message_data: Some(
                Ukey2ClientFinished {
                    public_key: Some(pkey.encode_to_vec()),
                }
                .encode_to_vec(),
            ),
        };

        let sha512 = Sha512::digest(finish_frame.encode_to_vec());
        let frame = Ukey2Message {
            message_type: Some(ukey2_message::Type::ClientInit.into()),
            message_data: Some(
                Ukey2ClientInit {
                    version: Some(1),
                    random: Some(gen_random(32)),
                    next_protocol: Some(String::from("AES_256_CBC-HMAC_SHA256")),
                    cipher_commitments: vec![CipherCommitment {
                        handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
                        commitment: Some(sha512.to_vec()),
                    }],
                }
                .encode_to_vec(),
            ),
        };

        self.send_frame(frame.encode_to_vec()).await?;

        self.update_state(
            |e| {
                e.state = TransferState::SentUkeyClientInit;
                e.private_key = Some(secret_key);
                e.public_key = Some(public_key);
                e.client_init_msg_data = Some(frame.encode_to_vec());
                e.ukey_client_finish_msg_data = Some(finish_frame.encode_to_vec());
            },
            false,
        )
        .await;

        Ok(())
    }

    async fn process_ukey2_server_init(&mut self, msg: &Ukey2Message) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ServerInit {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ServerInit",
                msg.message_type
            ));
        }

        let server_init = match Ukey2ServerInit::decode(msg.message_data()) {
            Ok(uk2si) => uk2si,
            Err(e) => {
                return Err(anyhow!("UKey2: Ukey2ClientFinished::decode: {e}"));
            }
        };

        if server_init.version() != 1 {
            self.send_ukey2_alert(AlertType::BadVersion).await?;
            return Err(anyhow!("UKey2: server_init.version != 1"));
        }

        if server_init.random().len() != 32 {
            self.send_ukey2_alert(AlertType::BadRandom).await?;
            return Err(anyhow!("UKey2: server_init.random.len != 32"));
        }

        if server_init.handshake_cipher() != Ukey2HandshakeCipher::P256Sha512 {
            self.send_ukey2_alert(AlertType::BadHandshakeCipher).await?;
            return Err(anyhow!("UKey2: handshake_cipher != P256Sha512"));
        }

        let server_public_key = match GenericPublicKey::decode(server_init.public_key()) {
            Ok(spk) => spk,
            Err(e) => {
                return Err(anyhow!("UKey2: GenericPublicKey::decode: {e}"));
            }
        };

        self.finalize_key_exchange(server_public_key).await?;
        let client_finish_data = self.state.ukey_client_finish_msg_data.clone()
            .ok_or_else(|| anyhow!("Missing ukey_client_finish_msg_data"))?;
        self.send_frame(client_finish_data).await?;

        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::ConnectionResponse.into(),
                ),
                connection_response: Some(location_nearby_connections::ConnectionResponseFrame {
					response: Some(location_nearby_connections::connection_response_frame::ResponseStatus::Accept.into()),
					os_info: Some(location_nearby_connections::OsInfo {
						r#type: Some(location_nearby_connections::os_info::OsType::Linux.into())
					}),
					// Version 6+ indicates PAYLOAD_RECEIVED_ACK support
					nearby_connections_version: Some(6),
					..Default::default()
				}),
                ..Default::default()
            }),
        };

        self.send_frame(frame.encode_to_vec()).await?;

        Ok(())
    }

    async fn process_connection_response(
        &mut self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionResponse
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let connection_response = v1_frame.connection_response.as_ref()
            .ok_or_else(|| anyhow!("Unexpected None connection_response"))?;

        if connection_response.response() != ResponseStatus::Accept {
            return Err(anyhow!("Connection rejected by third party"));
        }

        let paired_encryption = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyEncryption.into()),
                paired_key_encryption: Some(sharing_nearby::PairedKeyEncryptionFrame {
                    secret_id_hash: Some(gen_random(6)),
                    signed_data: Some(gen_random(72)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_encryption).await?;

        Ok(())
    }

    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    async fn decrypt_and_process_secure_message(
        &mut self,
        smsg: &SecureMessage,
    ) -> Result<(), anyhow::Error> {
        let recv_hmac_key = self.state.recv_hmac_key.as_ref()
            .ok_or_else(|| anyhow!("Missing recv_hmac_key"))?;
        let mut hmac = HmacSha256::new_from_slice(recv_hmac_key)?;
        hmac.update(&smsg.header_and_body);
        // Use constant-time comparison to prevent timing attacks
        hmac.verify_slice(smsg.signature.as_slice())
            .map_err(|_| anyhow!("HMAC verification failed"))?;

        let header_and_body = HeaderAndBody::decode(&*smsg.header_and_body)?;

        let msg_data = header_and_body.body;
        let key = self.state.decrypt_key.as_ref()
            .ok_or_else(|| anyhow!("Missing decrypt_key"))?;

        let mut cipher = Cipher::new_256(key[..AES_256_KEY_LEN].try_into()?);
        cipher.set_auto_padding(true);
        let decrypted = cipher.cbc_decrypt(header_and_body.header.iv(), &msg_data);

        let d2d_msg = DeviceToDeviceMessage::decode(&*decrypted)?;

        let seq = self.get_client_seq_inc().await;
        if d2d_msg.sequence_number() != seq {
            return Err(anyhow!(
                "Error d2d_msg.sequence_number invalid ({} vs {})",
                d2d_msg.sequence_number(),
                seq
            ));
        }

        let offline = location_nearby_connections::OfflineFrame::decode(d2d_msg.message())?;
        let v1_frame = offline
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;
        match v1_frame.r#type() {
            location_nearby_connections::v1_frame::FrameType::PayloadTransfer => {
                trace!("Received FrameType::PayloadTransfer");
                let payload_transfer = v1_frame
                    .payload_transfer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                let header = payload_transfer
                    .payload_header
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                // Check if this is a control message (ACK, error, cancel)
                if payload_transfer.packet_type() == PacketType::Control {
                    if let Some(control) = &payload_transfer.control_message {
                        use crate::location_nearby_connections::payload_transfer_frame::control_message::EventType;
                        let payload_id = header.id();
                        match control.event() {
                            EventType::PayloadReceivedAck => {
                                info!("Received PAYLOAD_RECEIVED_ACK for payload {payload_id}");
                                // Remove from pending set
                                self.state.pending_payload_acks.remove(&payload_id);

                                // If we were waiting for ACKs and all are received, request disconnect
                                if self.state.state == TransferState::WaitingForPayloadAck
                                    && self.state.pending_payload_acks.is_empty()
                                {
                                    info!("All payload ACKs received, requesting safe disconnect");
                                    self.update_state(|e| {
                                        e.state = TransferState::WaitingForDisconnectAck;
                                        // Reset timer for disconnect phase
                                        e.ack_wait_started = Some(std::time::Instant::now());
                                    }, false).await;
                                    self.request_disconnection().await?;
                                }
                            }
                            EventType::PayloadError => {
                                warn!("Received PAYLOAD_ERROR for payload {payload_id}");
                                // Remove from pending - we got a response even if it's an error
                                self.state.pending_payload_acks.remove(&payload_id);
                            }
                            EventType::PayloadCanceled => {
                                info!("Received PAYLOAD_CANCELED for payload {payload_id}");
                                self.state.pending_payload_acks.remove(&payload_id);
                            }
                            EventType::UnknownEventType => {
                                debug!("Received unknown control event for payload {payload_id}");
                            }
                        }
                    }
                    // Control messages don't have chunk data, so skip the rest
                    return Ok(());
                }

                let chunk = payload_transfer
                    .payload_chunk
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                match header.r#type() {
                    payload_header::PayloadType::Bytes => {
                        info!("Processing PayloadType::Bytes");
                        let payload_id = header.id();

                        if header.total_size() > i64::from(SANE_FRAME_LENGTH) {
                            self.state.payload_buffers.remove(&payload_id);
                            return Err(anyhow!(
                                "Payload too large: {} bytes",
                                header.total_size()
                            ));
                        }

                        // Prevent unbounded growth of payload buffers
                        if !self.state.payload_buffers.contains_key(&payload_id) && self.state.payload_buffers.len() >= 64 {
                            return Err(anyhow!("Too many concurrent payload buffers ({})", self.state.payload_buffers.len()));
                        }

                        self.state
                            .payload_buffers
                            .entry(payload_id)
                            .or_insert_with(|| Vec::with_capacity(usize::try_from(header.total_size()).unwrap_or_default()));

                        // Get the current length of the buffer, if it exists, without holding a mutable borrow.
                        let buffer_len = self.state.payload_buffers.get(&payload_id)
                            .ok_or_else(|| anyhow!("Missing payload buffer"))?.len();
                        let buffer_len_i64 = i64::try_from(buffer_len).unwrap_or(i64::MAX);
                        if chunk.offset() != buffer_len_i64 {
                            self.state.payload_buffers.remove(&payload_id);
                            return Err(anyhow!(
                                "Unexpected chunk offset: {}, expected: {}",
                                chunk.offset(),
                                buffer_len
                            ));
                        }

                        let buffer = self.state.payload_buffers.get_mut(&payload_id)
                            .ok_or_else(|| anyhow!("Missing payload buffer"))?;
                        if let Some(body) = &chunk.body {
                            buffer.extend(body);
                        }

                        if (chunk.flags() & 1) == 1 {
                            debug!("Chunk flags & 1 == 1 ?? End of data ??");

                            let inner_frame = sharing_nearby::Frame::decode(buffer.as_slice())?;
                            // Clean up completed buffer
                            self.state.payload_buffers.remove(&payload_id);
                            self.process_transfer_setup(&inner_frame).await?;
                        }
                    }
                    payload_header::PayloadType::File => {
                        error!("Unhandled PayloadType::File: {:?}", header.r#type());
                    }
                    payload_header::PayloadType::Stream => {
                        error!("Unhandled PayloadType::Stream: {:?}", header.r#type());
                    }
                    payload_header::PayloadType::UnknownPayloadType => {
                        error!(
                            "Invalid PayloadType::UnknownPayloadType: {:?}",
                            header.r#type()
                        );
                    }
                }
            }
            location_nearby_connections::v1_frame::FrameType::KeepAlive => {
                trace!("Sending keepalive");
                self.send_keepalive(true).await?;
            }
            location_nearby_connections::v1_frame::FrameType::Disconnection => {
                debug!("Received Disconnection frame");
                if let Some(disconnection) = &v1_frame.disconnection {
                    if disconnection.ack_safe_to_disconnect() {
                        info!("Received ack_safe_to_disconnect, transfer complete");
                        self.update_state(|e| { e.state = TransferState::Finished; }, true).await;
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                    if disconnection.request_safe_to_disconnect() {
                        // Receiver is requesting we disconnect - send ack and close
                        debug!("Receiver requested disconnection, sending ack");
                        self.send_disconnect_ack().await?;
                        self.update_state(|e| { e.state = TransferState::Finished; }, true).await;
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                }
            }
            _ => {
                debug!("Unhandled offline frame type: {:?}", v1_frame.r#type());
            }
        }

        Ok(())
    }

    async fn process_transfer_setup(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() == sharing_nearby::v1_frame::FrameType::Cancel {
            info!("Transfer canceled");
            self.update_state(
                |e| {
                    e.state = TransferState::Cancelled;
                },
                true,
            )
            .await;
            self.disconnection().await?;
            return Err(anyhow!(crate::errors::AppError::NotAnError));
        }

        match self.state.state {
            TransferState::SentPairedKeyEncryption => {
                debug!("Processing State::SentPairedKeyEncryption");
                self.process_paired_key_encryption_frame(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = TransferState::SentPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            TransferState::SentPairedKeyResult => {
                debug!("Processing State::SentPairedKeyResult");
                self.process_paired_key_result(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = TransferState::SentIntroduction;
                    },
                    true,
                )
                .await;
            }
            TransferState::SentIntroduction => {
                debug!("Processing State::SentIntroduction");
                self.process_consent(v1_frame).await?;
            }
            TransferState::SendingFiles => {}
            _ => {
                info!(
                    "Unhandled connection state in process_transfer_setup: {:?}",
                    self.state.state
                );
            }
        }

        Ok(())
    }

    async fn process_paired_key_encryption_frame(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_encryption.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        let paired_result = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyResult.into()),
                paired_key_result: Some(sharing_nearby::PairedKeyResultFrame {
                    status: Some(paired_key_result_frame::Status::Unable.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_result).await?;

        Ok(())
    }

    async fn process_paired_key_result(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_result.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        let mut file_metadata: Vec<FileMetadata> = vec![];
        let mut transferred_files: HashMap<i64, InternalFileInfo> = HashMap::new();
        let mut total_to_send = 0;
        // TODO - Handle sending Text
        match &self.payload {
            OutboundPayload::Files(files) => {
                for f in files {
                    let path = Path::new(f);
                    if !path.is_file() {
                        warn!("Path is not a file: {f}");
                        continue;
                    }

                    let file = match File::open(f) {
                        Ok(_f) => _f,
                        Err(e) => {
                            error!("Failed to open file: {f}: {e:?}");
                            continue;
                        }
                    };
                    let fmetadata = match file.metadata() {
                        Ok(_fm) => _fm,
                        Err(e) => {
                            error!("Failed to get metadata for: {f}: {e:?}");
                            continue;
                        }
                    };

                    let ftype = mime_guess::from_path(path)
                        .first_or_octet_stream()
                        .to_string();

                    let meta_type = if ftype.starts_with("image/") {
                        file_metadata::Type::Image
                    } else if ftype.starts_with("video/") {
                        file_metadata::Type::Video
                    } else if ftype.starts_with("audio/") {
                        file_metadata::Type::Audio
                    } else if path.extension().unwrap_or_default() == "apk" {
                        file_metadata::Type::App
                    } else {
                        file_metadata::Type::Unknown
                    };

                    info!("File type to send: {ftype}");
                    let fname = path
                        .file_name()
                        .ok_or_else(|| anyhow!("Failed to get file_name for {f}"))?;
                    let file_size = i64::try_from(fmetadata.size()).unwrap_or(i64::MAX);
                    let fmeta = FileMetadata {
                        payload_id: Some(rand::rng().random::<i64>()),
                        name: Some(fname.to_string_lossy().into_owned()),
                        size: Some(file_size),
                        mime_type: Some(ftype),
                        r#type: Some(meta_type.into()),
                        ..Default::default()
                    };
                    transferred_files.insert(
                        fmeta.payload_id(),
                        InternalFileInfo {
                            payload_id: fmeta.payload_id(),
                            file_url: path.to_path_buf(),
                            bytes_transferred: 0,
                            total_size: fmeta.size(),
                            file: Some(file),
                        },
                    );
                    file_metadata.push(fmeta);
                    total_to_send += fmetadata.size();
                }
            }
        }

        self.update_state(
            |e| {
                if let Some(tmd) = e.transfer_metadata.as_mut() {
                    tmd.total_bytes = total_to_send;
                }
                e.transferred_files = transferred_files;
            },
            false,
        )
        .await;

        let introduction = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Introduction.into()),
                introduction: Some(IntroductionFrame {
                    file_metadata,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&introduction).await?;

        Ok(())
    }

    /// Check if a cancellation request was received.
    /// Returns true if transfer should be cancelled.
    fn check_for_cancellation(&mut self) -> bool {
        match self.receiver.try_recv() {
            Ok(channel_msg) => {
                if channel_msg.id == self.state.id
                    && let channel::Message::Lib { action } = &channel_msg.msg
                {
                    debug!("outbound: got: {channel_msg:?}");
                    if action == &TransferAction::TransferCancel {
                        return true;
                    }
                }
                false
            }
            Err(TryRecvError::Empty) => false,
            Err(e) => {
                error!("outbound: channel error: {e}");
                false
            }
        }
    }

    /// Send a single file chunk and update state.
    /// Returns Ok(true) if more chunks to send, Ok(false) if file complete or should break.
    #[allow(clippy::too_many_lines)]
    async fn send_file_chunk(&mut self, file_id: i64) -> Result<bool, anyhow::Error> {
        // Workaround to limit scope of the immutable borrow on self
        let chunk_info = {
            let curr_state = match self.state.transferred_files.get(&file_id) {
                Some(s) => s,
                None => return Ok(false),
            };

            info!("> Currently sending {:?}", curr_state.file_url);
            if curr_state.bytes_transferred == curr_state.total_size {
                debug!("File {file_id} finished");
                self.update_state(|e| { e.transferred_files.remove(&file_id); }, false).await;
                return Ok(false);
            }

            let mut file = match curr_state.file.as_ref() {
                Some(f) => f,
                None => {
                    warn!("File {file_id} is none");
                    return Ok(false);
                }
            };

            let mut buffer = vec![0u8; 512 * 1024];
            let bytes_read = file.read(&mut buffer)?;

            Some((
                InternalFileInfo {
                    payload_id: curr_state.payload_id,
                    file_url: curr_state.file_url.clone(),
                    bytes_transferred: curr_state.bytes_transferred,
                    total_size: curr_state.total_size,
                    file: None,
                },
                buffer,
                bytes_read,
            ))
        };

        let Some((curr_state, buffer, bytes_read)) = chunk_info else {
            return Ok(false);
        };
        let bytes_read_i64 = i64::try_from(bytes_read).unwrap_or(i64::MAX);

        info!(
            "> File ready: {bytes_read} bytes, left to send: {}, offset: {}",
            curr_state.total_size - curr_state.bytes_transferred,
            curr_state.bytes_transferred
        );

        let payload_header = PayloadHeader {
            id: Some(file_id),
            r#type: Some(payload_header::PayloadType::File.into()),
            total_size: Some(curr_state.total_size),
            is_sensitive: Some(false),
            file_name: curr_state.file_url.file_name().map(|n| n.to_string_lossy().into_owned()),
            ..Default::default()
        };

        // Send the chunk
        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into()),
                payload_transfer: Some(PayloadTransferFrame {
                    packet_type: Some(PacketType::Data.into()),
                    payload_chunk: Some(PayloadChunk {
                        offset: Some(curr_state.bytes_transferred),
                        flags: Some(0),
                        body: Some(buffer[..bytes_read].to_vec()),
                    }),
                    payload_header: Some(payload_header.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        self.encrypt_and_send(&wrapper).await?;

        // Update transfer progress
        self.update_state(
            |e| {
                if let Some(mu) = e.transferred_files.get_mut(&file_id) {
                    mu.bytes_transferred += bytes_read_i64;
                }
                if let Some(tmd) = e.transfer_metadata.as_mut() {
                    tmd.ack_bytes += bytes_read as u64;
                }
            },
            true,
        ).await;

        // Check if this was the last chunk
        if curr_state.bytes_transferred + bytes_read_i64 == curr_state.total_size {
            debug!(
                "File {file_id} finished, offset: {} / total: {}",
                curr_state.bytes_transferred + bytes_read_i64,
                curr_state.total_size
            );

            // Send final chunk marker
            let final_wrapper = location_nearby_connections::OfflineFrame {
                version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
                v1: Some(location_nearby_connections::V1Frame {
                    r#type: Some(location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into()),
                    payload_transfer: Some(PayloadTransferFrame {
                        packet_type: Some(PacketType::Data.into()),
                        payload_chunk: Some(PayloadChunk {
                            offset: Some(curr_state.total_size),
                            flags: Some(1), // lastChunk
                            body: Some(vec![]),
                        }),
                        payload_header: Some(payload_header),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            };
            self.encrypt_and_send(&final_wrapper).await?;
            return Ok(false);
        }

        Ok(true)
    }

    /// Send all accepted files. Returns true if completed, false if cancelled.
    async fn send_accepted_files(&mut self) -> Result<bool, anyhow::Error> {
        let ids: Vec<i64> = self.state.transferred_files.keys().copied().collect();
        info!("We are sending: {ids:?}");

        // Track all payload IDs we're sending - we'll wait for ACKs for these
        self.state.pending_payload_acks = ids.iter().copied().collect();

        for file_id in ids {
            loop {
                // Check for cancellation before each chunk
                if self.check_for_cancellation() {
                    self.update_state(|e| { e.state = TransferState::Cancelled; }, true).await;
                    self.disconnection().await?;
                    return Ok(false);
                }

                if !self.send_file_chunk(file_id).await? {
                    break;
                }
            }
        }

        info!("All files have been sent, waiting for PAYLOAD_RECEIVED_ACK");

        // Transition to waiting for ACKs - the main handle loop will process them
        self.update_state(|e| {
            e.state = TransferState::WaitingForPayloadAck;
            e.ack_wait_started = Some(std::time::Instant::now());
        }, true).await;

        // If no files were sent (empty pending_payload_acks), request disconnect immediately
        if self.state.pending_payload_acks.is_empty() {
            info!("No payloads to wait for, requesting safe disconnect");
            self.update_state(|e| {
                e.state = TransferState::WaitingForDisconnectAck;
                // Reset timer for disconnect phase
                e.ack_wait_started = Some(std::time::Instant::now());
            }, false).await;
            self.request_disconnection().await?;
        }

        Ok(true)
    }

    /// Request safe disconnection from the receiver (sends request_safe_to_disconnect: true)
    async fn request_disconnection(&mut self) -> Result<(), anyhow::Error> {
        debug!("Sending request_safe_to_disconnect");
        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::Disconnection.into(),
                ),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    request_safe_to_disconnect: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&frame).await?;
        } else {
            self.send_frame(frame.encode_to_vec()).await?;
        }

        debug!("Waiting for ack_safe_to_disconnect");
        Ok(())
    }

    /// Send disconnect acknowledgment (sends ack_safe_to_disconnect: true)
    async fn send_disconnect_ack(&mut self) -> Result<(), anyhow::Error> {
        debug!("Sending ack_safe_to_disconnect");
        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::Disconnection.into(),
                ),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    ack_safe_to_disconnect: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&frame).await?;
        } else {
            self.send_frame(frame.encode_to_vec()).await?;
        }

        Ok(())
    }

    async fn process_consent(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.r#type() != sharing_nearby::v1_frame::FrameType::Response {
            return Err(anyhow!("Missing required fields"));
        }

        let connection_response = v1_frame.connection_response.as_ref()
            .ok_or_else(|| anyhow!("Missing connection_response"))?;

        match connection_response.status() {
            sharing_nearby::connection_response_frame::Status::Accept => {
                info!("State is now State::SendingFiles");
                self.update_state(|e| { e.state = TransferState::SendingFiles; }, true).await;
                self.send_accepted_files().await?;
            }
            sharing_nearby::connection_response_frame::Status::Reject
            | sharing_nearby::connection_response_frame::Status::NotEnoughSpace
            | sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType
            | sharing_nearby::connection_response_frame::Status::TimedOut => {
                warn!("Cannot process: consent denied: {:?}", connection_response.status());
                self.update_state(|e| { e.state = TransferState::Disconnected; }, true).await;
                self.disconnection().await?;
                return Err(anyhow!(crate::errors::AppError::NotAnError));
            }
            sharing_nearby::connection_response_frame::Status::Unknown => {
                error!("Unknown consent type: aborting");
                self.update_state(|e| { e.state = TransferState::Disconnected; }, true).await;
                self.disconnection().await?;
                return Err(anyhow!(crate::errors::AppError::NotAnError));
            }
        }

        Ok(())
    }

    async fn disconnection(&mut self) -> Result<(), anyhow::Error> {
        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::Disconnection.into(),
                ),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&frame).await
        } else {
            self.send_frame(frame.encode_to_vec()).await
        }
    }

    async fn finalize_key_exchange(
        &mut self,
        raw_peer_key: GenericPublicKey,
    ) -> Result<(), anyhow::Error> {
        let peer_p256_key = raw_peer_key
            .ec_p256_public_key
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let mut bytes = vec![0x04];
        // Ensure no more than 32 bytes for the keys
        if peer_p256_key.x.len() > 32 {
            bytes.extend_from_slice(&peer_p256_key.x[peer_p256_key.x.len() - 32..]);
        } else {
            bytes.extend_from_slice(&peer_p256_key.x);
        }
        if peer_p256_key.y.len() > 32 {
            bytes.extend_from_slice(&peer_p256_key.y[peer_p256_key.y.len() - 32..]);
        } else {
            bytes.extend_from_slice(&peer_p256_key.y);
        }

        let encoded_point = EncodedPoint::from_bytes(bytes)?;
        let peer_key: PublicKey = Option::from(PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| anyhow!("Invalid peer public key from encoded point"))?;
        let priv_key = self
            .state
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing private key for key exchange"))?;

        let dhs = diffie_hellman(priv_key.to_nonzero_scalar(), peer_key.as_affine());
        let derived_secret = Sha256::digest(dhs.raw_secret_bytes());

        let mut ukey_info: Vec<u8> = vec![];
        ukey_info.extend_from_slice(
            self.state
                .client_init_msg_data
                .as_ref()
                .ok_or_else(|| anyhow!("Missing client init message data"))?,
        );
        ukey_info.extend_from_slice(
            self.state
                .server_init_data
                .as_ref()
                .ok_or_else(|| anyhow!("Missing server init data"))?,
        );

        let auth_label = "UKEY2 v1 auth".as_bytes();
        let next_label = "UKEY2 v1 next".as_bytes();

        let auth_string = hkdf_extract_expand(auth_label, &derived_secret, &ukey_info, 32)?;
        let next_secret = hkdf_extract_expand(next_label, &derived_secret, &ukey_info, 32)?;

        let salt_hex = "82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510";
        let salt =
            hex::decode(salt_hex).map_err(|e| anyhow!("Failed to decode salt_hex: {e}"))?;

        let d2d_client = hkdf_extract_expand(&salt, &next_secret, "client".as_bytes(), 32)?;
        let d2d_server = hkdf_extract_expand(&salt, &next_secret, "server".as_bytes(), 32)?;

        let key_salt_hex = "BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E";
        let key_salt = hex::decode(key_salt_hex)
            .map_err(|e| anyhow!("Failed to decode key_salt_hex: {e}"))?;

        let client_key = hkdf_extract_expand(&key_salt, &d2d_client, "ENC:2".as_bytes(), 32)?;
        let client_hmac_key = hkdf_extract_expand(&key_salt, &d2d_client, "SIG:1".as_bytes(), 32)?;
        let server_key = hkdf_extract_expand(&key_salt, &d2d_server, "ENC:2".as_bytes(), 32)?;
        let server_hmac_key = hkdf_extract_expand(&key_salt, &d2d_server, "SIG:1".as_bytes(), 32)?;

        self.update_state(
            |e| {
                e.decrypt_key = Some(server_key);
                e.recv_hmac_key = Some(server_hmac_key);
                e.encrypt_key = Some(client_key);
                e.send_hmac_key = Some(client_hmac_key);
                e.pin_code = Some(to_four_digit_string(&auth_string));
                e.encryption_done = true;

                if let Some(ref mut tm) = e.transfer_metadata {
                    tm.pin_code = Some(to_four_digit_string(&auth_string));
                }
            },
            true,
        )
        .await;

        info!("Pin code: {:?}", self.state.pin_code);

        Ok(())
    }

    async fn send_ukey2_alert(&mut self, atype: AlertType) -> Result<(), anyhow::Error> {
        let alert = Ukey2Alert {
            r#type: Some(atype.into()),
            error_message: None,
        };

        let data = Ukey2Message {
            message_type: Some(atype.into()),
            message_data: Some(alert.encode_to_vec()),
        };

        self.send_frame(data.encode_to_vec()).await
    }

    async fn send_encrypted_frame(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let frame_data = frame.encode_to_vec();
        let body_size = frame_data.len();
        let body_size_i64 = i64::try_from(body_size).unwrap_or(i64::MAX);

        let payload_header = PayloadHeader {
            id: Some(rand::rng().random_range(i64::MIN..i64::MAX)),
            r#type: Some(payload_header::PayloadType::Bytes.into()),
            total_size: Some(body_size_i64),
            is_sensitive: Some(false),
            ..Default::default()
        };

        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(0),
                flags: Some(0),
                body: Some(frame_data),
            }),
            payload_header: Some(payload_header.clone()),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        // Send lastChunk
        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(body_size_i64),
                flags: Some(1), // lastChunk
                body: Some(vec![]),
            }),
            payload_header: Some(payload_header),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        Ok(())
    }

    async fn encrypt_and_send(&mut self, frame: &OfflineFrame) -> Result<(), anyhow::Error> {
        let d2d_msg = DeviceToDeviceMessage {
            sequence_number: Some(self.get_server_seq_inc().await),
            message: Some(frame.encode_to_vec()),
        };

        let key = self
            .state
            .encrypt_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing encryption key"))?;
        let msg_data = d2d_msg.encode_to_vec();
        let iv = gen_random(16);

        let key_bytes: &[u8; AES_256_KEY_LEN] = key[..AES_256_KEY_LEN]
            .try_into()
            .map_err(|_| anyhow!("Invalid encryption key length"))?;
        let mut cipher = Cipher::new_256(key_bytes);
        cipher.set_auto_padding(true);
        let encrypted = cipher.cbc_encrypt(&iv, &msg_data);

        let hb = HeaderAndBody {
            body: encrypted,
            header: Header {
                encryption_scheme: EncScheme::Aes256Cbc.into(),
                signature_scheme: SigScheme::HmacSha256.into(),
                iv: Some(iv),
                public_metadata: Some(
                    GcmMetadata {
                        r#type: Type::DeviceToDeviceMessage.into(),
                        version: Some(1),
                    }
                    .encode_to_vec(),
                ),
                ..Default::default()
            },
        };

        let hmac_key = self
            .state
            .send_hmac_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing HMAC key for sending"))?;
        let mut hmac = HmacSha256::new_from_slice(hmac_key)?;
        hmac.update(&hb.encode_to_vec());
        let result = hmac.finalize();

        let smsg = SecureMessage {
            header_and_body: hb.encode_to_vec(),
            signature: result.into_bytes().to_vec(),
        };

        self.send_frame(smsg.encode_to_vec()).await?;

        Ok(())
    }

    async fn send_keepalive(&mut self, ack: bool) -> Result<(), anyhow::Error> {
        let ack_frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(location_nearby_connections::v1_frame::FrameType::KeepAlive.into()),
                keep_alive: Some(KeepAliveFrame { ack: Some(ack) }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&ack_frame).await
        } else {
            self.send_frame(ack_frame.encode_to_vec()).await
        }
    }

    async fn send_frame(&mut self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        let length: u32 = data.len().try_into().map_err(|_| anyhow!("Frame too large"))?;

        let mut prefixed_length = Vec::with_capacity(data.len() + 4);
        prefixed_length.extend_from_slice(&length.to_be_bytes());
        prefixed_length.extend_from_slice(&data);

        self.socket.write_all(&prefixed_length).await?;
        self.socket.flush().await?;

        Ok(())
    }

    async fn get_server_seq_inc(&mut self) -> i32 {
        self.update_state(
            |e| {
                e.server_seq += 1;
            },
            false,
        )
        .await;

        self.state.server_seq
    }

    async fn get_client_seq_inc(&mut self) -> i32 {
        self.update_state(
            |e| {
                e.client_seq += 1;
            },
            false,
        )
        .await;

        self.state.client_seq
    }

    async fn update_state<F>(&mut self, f: F, inform: bool)
    where
        F: FnOnce(&mut InnerState),
    {
        f(&mut self.state);

        if !inform {
            return;
        }

        drop(self.sender.send(ChannelMessage {
            id: self.state.id.clone(),
            msg: channel::Message::Client(MessageClient {
                kind: TransferKind::Outbound,
                state: Some(self.state.state.clone()),
                metadata: self.state.transfer_metadata.clone(),
            }),
        }));
        // Add a small sleep timer to allow the Tokio runtime to have
        // some spare time to process channel's message. Otherwise it
        // get spammed by new requests. Currently set to 10 micro secs.
        tokio::time::sleep(SANITY_DURATION).await;
    }
}
