use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};
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
use tokio::sync::broadcast::{Receiver, Sender};

use super::{InnerState, TransferState};
use crate::channel::{self, ChannelMessage, MessageClient, TransferAction, TransferKind};
use crate::hdl::TextPayloadInfo;
use crate::hdl::info::{InternalFileInfo, TransferMetadata, TransferPayload, TransferPayloadKind};
use crate::location_nearby_connections::payload_transfer_frame::{
    ControlMessage, PacketType, PayloadChunk, PayloadHeader, control_message, payload_header,
};
use crate::location_nearby_connections::{KeepAliveFrame, OfflineFrame, PayloadTransferFrame};
use crate::securegcm::ukey2_alert::AlertType;
use crate::securegcm::{
    DeviceToDeviceMessage, GcmMetadata, Type, Ukey2Alert, Ukey2ClientFinished, Ukey2ClientInit,
    Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit, ukey2_message,
};
use crate::securemessage::{
    EcP256PublicKey, EncScheme, GenericPublicKey, Header, HeaderAndBody, PublicKeyType,
    SecureMessage, SigScheme,
};
use crate::sharing_nearby::wifi_credentials_metadata::SecurityType;
use crate::sharing_nearby::{paired_key_result_frame, text_metadata};
use crate::utils::{
    DeviceType, RemoteDeviceInfo, encode_point, gen_ecdsa_keypair, gen_random, get_download_dir,
    hkdf_extract_expand, stream_read_exact, to_four_digit_string,
};
use crate::{location_nearby_connections, sharing_nearby};

type HmacSha256 = Hmac<Sha256>;

const SANE_FRAME_LENGTH: i32 = 5 * 1024 * 1024;
const SANITY_DURATION: Duration = Duration::from_micros(10);

#[derive(Debug)]
pub struct InboundRequest {
    socket: TcpStream,
    pub state: InnerState,
    sender: Sender<ChannelMessage>,
    receiver: Receiver<ChannelMessage>,
}

impl InboundRequest {
    pub fn new(socket: TcpStream, id: String, sender: Sender<ChannelMessage>) -> Self {
        let receiver = sender.subscribe();

        Self {
            socket,
            state: InnerState::new(id, None),
            sender,
            receiver,
        }
    }

    pub async fn handle(&mut self) -> Result<(), anyhow::Error> {
        // Buffer for the 4-byte length
        let mut length_buf = [0u8; 4];

        tokio::select! {
            i = self.receiver.recv() => {
                match i {
                    Ok(channel_msg) => {
                        if channel_msg.id != self.state.id {
                            return Ok(());
                        }

                        if let channel::Message::Lib { action } = &channel_msg.msg {
                            debug!("inbound: got: {channel_msg:?}");
                            match action {
                                TransferAction::ConsentAccept => {
                                    self.accept_transfer().await?;
                                },
                                TransferAction::ConsentDecline => {
                                    self.update_state(
                                        |e| {
                                            e.state = TransferState::Rejected;
                                        },
                                        true,
                                    ).await;

                                    self.reject_transfer(Some(
                                        sharing_nearby::connection_response_frame::Status::Reject
                                    )).await?;
                                    return Err(anyhow!(crate::errors::AppError::NotAnError));
                                },
                                TransferAction::TransferCancel => {
                                    self.update_state(
                                        |e| {
                                            e.state = TransferState::Cancelled;
                                        },
                                        true,
                                    ).await;
                                    self.disconnection().await?;
                                    return Err(anyhow!(crate::errors::AppError::NotAnError));
                                },
                            }
                        }

                    }
                    Err(e) => {
                        error!("inbound: channel error: {e}");
                    }
                }
            },
            h = stream_read_exact(&mut self.socket, &mut length_buf) => {
                h?;

                self._handle(length_buf).await?;
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
            TransferState::Initial => {
                debug!("Handling State::Initial frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                let rdi = self.process_connection_request(&frame)?;
                info!("RemoteDeviceInfo: {:?}", &rdi);

                // Advance current state
                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::ReceivedConnectionRequest;
                        e.remote_device_info = Some(rdi);
                    },
                    false,
                )
                .await;
            }
            TransferState::ReceivedConnectionRequest => {
                debug!("Handling State::ReceivedConnectionRequest frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_init(&msg).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::SentUkeyServerInit;
                        e.client_init_msg_data = Some(frame_data);
                    },
                    false,
                )
                .await;
            }
            TransferState::SentUkeyServerInit => {
                debug!("Handling State::SentUkeyServerInit frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_finish(&msg, &frame_data).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::ReceivedUkeyClientFinish;
                    },
                    false,
                )
                .await;
            }
            TransferState::ReceivedUkeyClientFinish => {
                debug!("Handling State::ReceivedUkeyClientFinish frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                self.process_connection_response(&frame).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::SentConnectionResponse;
                    },
                    false,
                )
                .await;
            }
            // Only process encrypted messages after key exchange is complete
            TransferState::SentConnectionResponse
            | TransferState::SentPairedKeyResult
            | TransferState::ReceivedPairedKeyResult
            | TransferState::WaitingForUserConsent
            | TransferState::ReceivingFiles => {
                debug!("Handling SecureMessage frame in state {:?}", current_state.state);
                let smsg = SecureMessage::decode(&*frame_data)?;
                self.decrypt_and_process_secure_message(&smsg).await?;
            }
            // Reject messages in invalid states
            _ => {
                return Err(anyhow!(
                    "Unexpected message in state {:?}",
                    current_state.state
                ));
            }
        }

        Ok(())
    }

    fn process_connection_request(
        &self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<RemoteDeviceInfo, anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionRequest
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let connection_request = v1_frame
            .connection_request
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let endpoint_info = connection_request
            .endpoint_info
            .as_ref()
            .ok_or_else(|| anyhow!("Missing endpoint info"))?;

        // Check if endpoint info length is greater than 17
        if endpoint_info.len() <= 17 {
            return Err(anyhow!("Endpoint info too short"));
        }

        let device_name_length = endpoint_info[17] as usize;
        // Validate length including device name
        if endpoint_info.len() < device_name_length + 18 {
            return Err(anyhow!(
                "Endpoint info too short to contain the device name"
            ));
        }

        // Extract and validate device name based on length
        let device_name = std::str::from_utf8(&endpoint_info[18..(18 + device_name_length)])
            .map_err(|_| anyhow!("Device name is not valid UTF-8"))?;

        // Parsing the device type
        let raw_device_type = (endpoint_info[0] & 7) >> 1_usize;

        Ok(RemoteDeviceInfo {
            name: device_name.to_string(),
            device_type: DeviceType::from_raw_value(raw_device_type),
        })
    }

    async fn process_ukey2_client_init(&mut self, msg: &Ukey2Message) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientInit {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientInit",
                msg.message_type
            ));
        }

        let client_init = match Ukey2ClientInit::decode(msg.message_data()) {
            Ok(uk2ci) => uk2ci,
            Err(e) => {
                self.send_ukey2_alert(AlertType::BadMessageData).await?;
                return Err(anyhow!("UKey2: Ukey2ClientInit::decode: {e}"));
            }
        };

        if client_init.version() != 1 {
            self.send_ukey2_alert(AlertType::BadVersion).await?;
            return Err(anyhow!("UKey2: client_init.version != 1"));
        }

        if client_init.random().len() != 32 {
            self.send_ukey2_alert(AlertType::BadRandom).await?;
            return Err(anyhow!("UKey2: client_init.random.len != 32"));
        }

        // Searching for preferred cipher commitment
        let mut found = false;
        for commitment in &client_init.cipher_commitments {
            trace!("CipherCommitment: {:?}", commitment.handshake_cipher());
            if Ukey2HandshakeCipher::P256Sha512 == commitment.handshake_cipher() {
                found = true;
                self.update_state(
                    |e| {
                        e.cipher_commitment = Some(commitment.clone());
                    },
                    false,
                )
                .await;
                break;
            }
        }

        if !found {
            self.send_ukey2_alert(AlertType::BadHandshakeCipher).await?;
            return Err(anyhow!("UKey2: badHandshakeCipher"));
        }

        if client_init.next_protocol() != "AES_256_CBC-HMAC_SHA256" {
            self.send_ukey2_alert(AlertType::BadNextProtocol).await?;
            return Err(anyhow!(
                "UKey2: badNextProtocol: {}",
                client_init.next_protocol()
            ));
        }

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

        let server_init = Ukey2ServerInit {
            version: Some(1),
            random: Some(rand::rng().random::<[u8; 32]>().to_vec()),
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
            public_key: Some(pkey.encode_to_vec()),
        };

        let server_init_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ServerInit.into()),
            message_data: Some(server_init.encode_to_vec()),
        };

        let server_init_data = server_init_msg.encode_to_vec();
        self.update_state(
            |e| {
                e.private_key = Some(secret_key);
                e.public_key = Some(public_key);
                e.server_init_data = Some(server_init_data.clone());
            },
            false,
        )
        .await;

        self.send_frame(server_init_data).await?;

        Ok(())
    }

    async fn process_ukey2_client_finish(
        &mut self,
        msg: &Ukey2Message,
        frame_data: &Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientFinish {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientFinish",
                msg.message_type
            ));
        }

        let sha512 = Sha512::digest(frame_data);
        let cipher_commitment = self.state.cipher_commitment.as_ref()
            .ok_or_else(|| anyhow!("Missing cipher_commitment"))?;
        if cipher_commitment.commitment() != &sha512[..] {
            error!("cipher_commitment isn't equals to sha512(frame_data)");
            return Err(anyhow!("UKey2: cipher_commitment != sha512"));
        }

        let client_finish = match Ukey2ClientFinished::decode(msg.message_data()) {
            Ok(uk2cf) => uk2cf,
            Err(e) => {
                return Err(anyhow!("UKey2: Ukey2ClientFinished::decode: {e}"));
            }
        };

        if client_finish.public_key.is_none() {
            return Err(anyhow!("UKey2: client_finish.public_key None"));
        }

        let client_public_key = match GenericPublicKey::decode(client_finish.public_key()) {
            Ok(cpk) => cpk,
            Err(e) => {
                return Err(anyhow!("UKey2: GenericPublicKey::decode: {e}"));
            }
        };

        self.finalize_key_exchange(client_public_key).await?;

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

        let response = location_nearby_connections::OfflineFrame {
			version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
			v1: Some(location_nearby_connections::V1Frame {
				r#type: Some(location_nearby_connections::v1_frame::FrameType::ConnectionResponse.into()),
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
			})
		};

        self.send_frame(response.encode_to_vec()).await?;

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

    /// Parse WiFi password from payload buffer.
    fn parse_wifi_password(buffer: &[u8]) -> anyhow::Result<String> {
        if buffer.len() < 4 {
            anyhow::bail!("Buffer too short ({buffer:?})");
        }

        if buffer[buffer.len() - 2] != 0x10 {
            anyhow::bail!("Buffer ({buffer:?}) doesn't end with 0x10 0x?? as expected");
        }

        let len = buffer[1] as usize;
        let payload_buffer = buffer
            .get(2..2 + len)
            .with_context(|| anyhow!("Buffer too short, can't retrieve payload of length {len}"))?;

        Ok(String::from_utf8(payload_buffer.to_vec())?)
    }

    /// Complete a text payload transfer (URL, text, or WiFi credentials).
    async fn finish_text_transfer(&mut self, buffer: &mut [u8]) -> Result<(), anyhow::Error> {
        info!("Transfer finished");

        let text_payload = self.state.text_payload.clone()
            .ok_or_else(|| anyhow!("Missing text_payload"))?;
        match text_payload {
            TextPayloadInfo::Url(_) => {
                let payload = std::str::from_utf8(buffer)?.to_owned();
                self.update_state(
                    |e| {
                        if let Some(tmd) = e.transfer_metadata.as_mut() {
                            tmd.payload = Some(TransferPayload::Url(payload));
                        }
                    },
                    false,
                ).await;
            }
            TextPayloadInfo::Text(_) => {
                let payload = std::str::from_utf8(buffer)?.to_owned();
                self.update_state(
                    |e| {
                        if let Some(tmd) = e.transfer_metadata.as_mut() {
                            tmd.payload = Some(TransferPayload::Text(payload));
                        }
                    },
                    false,
                ).await;
            }
            TextPayloadInfo::Wifi((_, ssid, security_type)) => {
                let payload = match security_type {
                    kind @ SecurityType::UnknownSecurityType => kind.as_str_name().into(),
                    SecurityType::Open => String::new(),
                    SecurityType::WpaPsk | SecurityType::Wep => {
                        Self::parse_wifi_password(buffer)
                            .inspect_err(|err| error!("{err:#}"))
                            .unwrap_or_default()
                    }
                };

                self.update_state(
                    |e| {
                        if let Some(tmd) = e.transfer_metadata.as_mut() {
                            tmd.payload = Some(TransferPayload::Wifi {
                                ssid,
                                password: payload,
                                security_type,
                            });
                        }
                    },
                    false,
                ).await;
            }
        }

        self.update_state(|e| { e.state = TransferState::Finished; }, true).await;
        self.disconnection().await?;
        Err(anyhow!(crate::errors::AppError::NotAnError))
    }

    /// Process a bytes payload chunk.
    async fn process_bytes_payload(
        &mut self,
        header: &PayloadHeader,
        chunk: &PayloadChunk,
    ) -> Result<(), anyhow::Error> {
        info!("Processing PayloadType::Bytes");
        let payload_id = header.id();

        if header.total_size() > i64::from(SANE_FRAME_LENGTH) {
            self.state.payload_buffers.remove(&payload_id);
            return Err(anyhow!("Payload too large: {} bytes", header.total_size()));
        }

        self.state
            .payload_buffers
            .entry(payload_id)
            .or_insert_with(|| Vec::with_capacity(usize::try_from(header.total_size()).unwrap_or_default()));

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

        if let Some(buffer) = self.state.payload_buffers.get_mut(&payload_id)
            && let Some(body) = &chunk.body
        {
            buffer.extend(body);
        }

        // Check if this is the final chunk
        if (chunk.flags() & 1) == 1 {
            debug!("End of bytes payload");

            let is_text_payload = self.state.text_payload.as_ref()
                .is_some_and(|tp| tp.get_i64_value() == payload_id);

            // Take the buffer out to release the borrow
            let mut buffer = self.state.payload_buffers.remove(&payload_id)
                .ok_or_else(|| anyhow!("Missing payload buffer"))?;

            if is_text_payload {
                return self.finish_text_transfer(&mut buffer).await;
            }

            let inner_frame = sharing_nearby::Frame::decode(buffer.as_slice())?;
            self.process_transfer_setup(&inner_frame).await?;
        }

        Ok(())
    }

    /// Process a file payload chunk.
    async fn process_file_payload(
        &mut self,
        header: &PayloadHeader,
        chunk: &PayloadChunk,
    ) -> Result<(), anyhow::Error> {
        info!("Processing PayloadType::File");
        let payload_id = header.id();

        let file_internal = self
            .state
            .transferred_files
            .get_mut(&payload_id)
            .ok_or_else(|| anyhow!("File payload ID ({payload_id}) is not known"))?;

        let current_offset = file_internal.bytes_transferred;
        if chunk.offset() != current_offset {
            return Err(anyhow!(
                "Invalid offset into file {}, expected {}",
                chunk.offset(),
                current_offset
            ));
        }

        let chunk_size = chunk.body().len();
        let chunk_size_i64 = i64::try_from(chunk_size).unwrap_or(i64::MAX);
        if current_offset + chunk_size_i64 > file_internal.total_size {
            return Err(anyhow!(
                "Transferred file size exceeds previously specified value: {} vs {}",
                current_offset + chunk_size_i64,
                file_internal.total_size
            ));
        }

        if !chunk.body().is_empty() {
            let file = file_internal.file.as_ref()
                .ok_or_else(|| anyhow!("File handle not available"))?;
            file.write_all_at(chunk.body(), u64::try_from(current_offset).unwrap_or_default())?;
            file_internal.bytes_transferred += chunk_size_i64;

            self.update_state(
                |e| {
                    if let Some(tmd) = e.transfer_metadata.as_mut() {
                        tmd.ack_bytes += chunk_size as u64;
                    }
                },
                true,
            ).await;
        } else if (chunk.flags() & 1) == 1 {
            // Final chunk marker - send ACK to sender before removing from tracking
            self.send_payload_received_ack(payload_id).await?;

            self.state.transferred_files.remove(&payload_id);
            if self.state.transferred_files.is_empty() {
                info!("All files received, transfer finished");
                self.update_state(|e| { e.state = TransferState::Finished; }, true).await;
                // Don't disconnect - wait for sender to request safe disconnect
            }
        }

        Ok(())
    }

    /// Process a control message (error, cancel, ack).
    async fn process_control_message(
        &mut self,
        header: &PayloadHeader,
        control: &location_nearby_connections::payload_transfer_frame::ControlMessage,
    ) -> Result<(), anyhow::Error> {
        use location_nearby_connections::payload_transfer_frame::control_message::EventType;

        let payload_id = header.id();
        match control.event() {
            EventType::PayloadError => {
                warn!("Received PAYLOAD_ERROR for payload {payload_id}");
                // Clean up the failed transfer
                self.state.transferred_files.remove(&payload_id);
                self.state.payload_buffers.remove(&payload_id);
            }
            EventType::PayloadCanceled => {
                info!("Received PAYLOAD_CANCELED for payload {payload_id}");
                // Clean up the canceled transfer
                self.state.transferred_files.remove(&payload_id);
                self.state.payload_buffers.remove(&payload_id);
            }
            EventType::PayloadReceivedAck => {
                debug!("Received PAYLOAD_RECEIVED_ACK for payload {payload_id} at offset {}", control.offset());
            }
            EventType::UnknownEventType => {
                warn!("Received unknown control event for payload {payload_id}");
            }
        }
        Ok(())
    }

    /// Process a payload transfer frame.
    async fn process_payload_transfer(
        &mut self,
        v1_frame: &location_nearby_connections::V1Frame,
    ) -> Result<(), anyhow::Error> {
        use location_nearby_connections::payload_transfer_frame::PacketType;

        trace!("Received FrameType::PayloadTransfer");
        let payload_transfer = v1_frame
            .payload_transfer
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let header = payload_transfer
            .payload_header
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        // Check packet type - could be DATA or CONTROL
        match payload_transfer.packet_type() {
            PacketType::Control => {
                let control = payload_transfer
                    .control_message
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing control_message in CONTROL packet"))?;
                return self.process_control_message(header, control).await;
            }
            PacketType::Data | PacketType::UnknownPacketType => {
                // Continue with normal data processing
            }
        }

        let chunk = payload_transfer
            .payload_chunk
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        match header.r#type() {
            payload_header::PayloadType::Bytes => self.process_bytes_payload(header, chunk).await,
            payload_header::PayloadType::File => self.process_file_payload(header, chunk).await,
            payload_header::PayloadType::Stream => {
                // Handle stream similarly to bytes - accumulate and process
                debug!("Processing PayloadType::Stream as bytes");
                self.process_bytes_payload(header, chunk).await
            }
            payload_header::PayloadType::UnknownPayloadType => {
                warn!("Received UnknownPayloadType, ignoring");
                Ok(())
            }
        }
    }

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
        let key = self.state.decrypt_key.as_ref()
            .ok_or_else(|| anyhow!("Missing decrypt_key"))?;

        let mut cipher = Cipher::new_256(key[..AES_256_KEY_LEN].try_into()?);
        cipher.set_auto_padding(true);
        let decrypted = cipher.cbc_decrypt(header_and_body.header.iv(), &header_and_body.body);

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
                self.process_payload_transfer(v1_frame).await?;
            }
            location_nearby_connections::v1_frame::FrameType::KeepAlive => {
                trace!("Sending keepalive");
                self.send_keepalive(true).await?;
            }
            location_nearby_connections::v1_frame::FrameType::Disconnection => {
                debug!("Received Disconnection frame");
                if let Some(disconnection) = &v1_frame.disconnection {
                    if disconnection.request_safe_to_disconnect() {
                        // Sender is requesting safe disconnect - send ack
                        info!("Received request_safe_to_disconnect, sending ack");
                        self.send_disconnect_ack().await?;
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                    if disconnection.ack_safe_to_disconnect() {
                        // Sender acknowledged our disconnect request
                        info!("Received ack_safe_to_disconnect, closing");
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                }
            }
            location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeRetry => {
                debug!("Received BANDWIDTH_UPGRADE_RETRY frame (ignoring)");
            }
            location_nearby_connections::v1_frame::FrameType::AutoResume => {
                debug!("Received AUTO_RESUME frame (ignoring)");
            }
            location_nearby_connections::v1_frame::FrameType::AutoReconnect => {
                debug!("Received AUTO_RECONNECT frame (ignoring)");
            }
            location_nearby_connections::v1_frame::FrameType::AuthenticationMessage
            | location_nearby_connections::v1_frame::FrameType::AuthenticationResult => {
                debug!("Received authentication frame (ignoring)");
            }
            _ => {
                warn!("Unhandled offline frame: {:?}", v1_frame.r#type());
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
            TransferState::SentConnectionResponse => {
                debug!("Processing State::SentConnectionResponse");
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
                        e.state = TransferState::ReceivedPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            TransferState::ReceivedPairedKeyResult => {
                debug!("Processing State::ReceivedPairedKeyResult");
                self.process_introduction(v1_frame).await?;
            }
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
        &self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_result.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        Ok(())
    }

    async fn process_introduction(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        let introduction = v1_frame
            .introduction
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        // No need to inform the channel here, we'll do it anyway with files info
        self.update_state(|e| e.state = TransferState::WaitingForUserConsent, false)
            .await;

        if !introduction.file_metadata.is_empty() && introduction.text_metadata.is_empty() {
            self.process_file_introduction(&introduction.file_metadata).await
        } else if introduction.text_metadata.len() == 1 {
            let meta = introduction.text_metadata.first()
                .ok_or_else(|| anyhow!("Missing text_metadata"))?;
            self.process_text_introduction(meta).await
        } else if introduction.wifi_credentials_metadata.len() == 1 {
            let meta = introduction.wifi_credentials_metadata.first()
                .ok_or_else(|| anyhow!("Missing wifi_credentials_metadata"))?;
            self.process_wifi_introduction(meta).await
        } else {
            self.reject_transfer(Some(
                sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
            ))
            .await
        }
    }

    /// Sanitize file name by replacing dangerous characters.
    /// Prevents path traversal and filesystem issues.
    fn sanitize_filename(name: &str) -> String {
        // Replace dangerous characters: / \ ? % * : | " < > =
        // Also handle path traversal attempts
        let sanitized: String = name
            .chars()
            .map(|c| match c {
                '/' | '\\' | '?' | '%' | '*' | ':' | '|' | '"' | '<' | '>' | '=' => '_',
                _ => c,
            })
            .collect();

        // Remove any remaining path components (.. or leading /)
        let sanitized = sanitized.trim_start_matches('.');
        let sanitized = sanitized.trim_start_matches('/');
        let sanitized = sanitized.trim_start_matches('\\');

        // If empty after sanitization, use a default name
        if sanitized.is_empty() {
            "unnamed_file".to_string()
        } else {
            sanitized.to_string()
        }
    }

    /// Resolve filename conflicts by appending (1), (2), etc.
    fn resolve_filename_conflict(base_dir: &Path, file_name: &str) -> PathBuf {
        let safe_name = Self::sanitize_filename(file_name);
        let mut dest = base_dir.to_path_buf();
        dest.push(&safe_name);

        if !dest.exists() {
            return dest;
        }

        dest.pop();
        let file_path = PathBuf::from(&safe_name);
        let stem = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or(&safe_name);
        let ext = file_path.extension();

        for counter in 1.. {
            let new_stem = format!("{stem} ({counter})");
            let new_name = match ext {
                Some(e) => PathBuf::from(new_stem).with_extension(e),
                None => PathBuf::from(new_stem),
            };
            dest.push(new_name);
            if !dest.exists() {
                return dest;
            }
            dest.pop();
        }

        dest // Unreachable in practice
    }

    async fn process_file_introduction(
        &mut self,
        file_metadata: &[sharing_nearby::FileMetadata],
    ) -> Result<(), anyhow::Error> {
        trace!("process_introduction: handling file_metadata");
        let mut files_name = Vec::with_capacity(file_metadata.len());
        let mut total_bytes: u64 = 0;
        let download_dir = get_download_dir();

        for file in file_metadata {
            info!("File name: {}", file.name());
            let dest = Self::resolve_filename_conflict(&download_dir, file.name());
            info!("Destination: {dest:?}");

            let info = InternalFileInfo {
                payload_id: file.payload_id(),
                file_url: dest,
                bytes_transferred: 0,
                total_size: file.size(),
                file: None,
            };
            total_bytes += u64::try_from(info.total_size).unwrap_or_default();
            self.state.transferred_files.insert(file.payload_id(), info);
            files_name.push(file.name().to_owned());
        }

        let metadata = TransferMetadata {
            id: self.state.id.clone(),
            source: self.state.remote_device_info.clone(),
            payload_kind: TransferPayloadKind::Files,
            payload_preview: Default::default(),
            payload: Some(TransferPayload::Files(files_name)),
            pin_code: self.state.pin_code.clone(),
            total_bytes,
            ack_bytes: Default::default(),
        };

        info!("Asking for user consent: {metadata:?}");
        self.update_state(|e| e.transfer_metadata = Some(metadata), true).await;
        Ok(())
    }

    async fn process_text_introduction(
        &mut self,
        meta: &sharing_nearby::TextMetadata,
    ) -> Result<(), anyhow::Error> {
        trace!("process_introduction: handling text_metadata");

        let (payload_kind, text_payload) = match meta.r#type() {
            text_metadata::Type::Url => {
                (TransferPayloadKind::Url, TextPayloadInfo::Url(meta.payload_id()))
            }
            text_metadata::Type::PhoneNumber
            | text_metadata::Type::Address
            | text_metadata::Type::Text => {
                (TransferPayloadKind::Text, TextPayloadInfo::Text(meta.payload_id()))
            }
            text_metadata::Type::Unknown => {
                return self.reject_transfer(Some(
                    sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
                ))
                .await;
            }
        };

        let metadata = TransferMetadata {
            id: self.state.id.clone(),
            source: self.state.remote_device_info.clone(),
            payload_kind,
            payload_preview: Some(meta.text_title.clone().unwrap_or_default()),
            pin_code: self.state.pin_code.clone(),
            payload: Default::default(),
            total_bytes: Default::default(),
            ack_bytes: Default::default(),
        };

        info!("Asking for user consent: {metadata:?}");
        self.update_state(
            |e| {
                e.text_payload = Some(text_payload);
                e.transfer_metadata = Some(metadata);
            },
            true,
        )
        .await;
        Ok(())
    }

    async fn process_wifi_introduction(
        &mut self,
        meta: &sharing_nearby::WifiCredentialsMetadata,
    ) -> Result<(), anyhow::Error> {
        trace!("process_introduction: handling wifi_credentials_metadata");

        let metadata = TransferMetadata {
            id: self.state.id.clone(),
            source: self.state.remote_device_info.clone(),
            payload_kind: TransferPayloadKind::WiFi,
            payload_preview: Some(meta.ssid.clone().unwrap_or_default()),
            pin_code: self.state.pin_code.clone(),
            payload: Default::default(),
            total_bytes: Default::default(),
            ack_bytes: Default::default(),
        };

        self.update_state(
            |e| {
                e.text_payload = Some(TextPayloadInfo::Wifi((
                    meta.payload_id(),
                    meta.ssid().to_owned(),
                    meta.security_type(),
                )));
                e.transfer_metadata = Some(metadata);
            },
            true,
        )
        .await;
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

    /// Send PAYLOAD_RECEIVED_ACK control message to sender after receiving a complete file.
    /// This tells the sender we've received all the data for this payload.
    /// Retries up to 3 times with 50ms delay between attempts (matching Google's implementation).
    async fn send_payload_received_ack(&mut self, payload_id: i64) -> Result<(), anyhow::Error> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 50;

        info!("Sending PAYLOAD_RECEIVED_ACK for payload {payload_id}");

        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(PayloadTransferFrame {
                    packet_type: Some(PacketType::Control.into()),
                    payload_header: Some(PayloadHeader {
                        id: Some(payload_id),
                        r#type: Some(payload_header::PayloadType::File.into()),
                        ..Default::default()
                    }),
                    control_message: Some(ControlMessage {
                        event: Some(control_message::EventType::PayloadReceivedAck.into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        let mut last_error = None;
        for attempt in 1..=MAX_RETRIES {
            let result = if self.state.encryption_done {
                self.encrypt_and_send(&frame).await
            } else {
                self.send_frame(frame.encode_to_vec()).await
            };

            match result {
                Ok(()) => {
                    debug!("PAYLOAD_RECEIVED_ACK sent successfully on attempt {attempt}");
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to send PAYLOAD_RECEIVED_ACK (attempt {attempt}/{MAX_RETRIES}): {e}");
                    last_error = Some(e);
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                    }
                }
            }
        }

        // All retries failed, return the last error
        Err(last_error.unwrap_or_else(|| anyhow!("Failed to send PAYLOAD_RECEIVED_ACK after {MAX_RETRIES} attempts")))
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
            self.encrypt_and_send(&frame).await
        } else {
            self.send_frame(frame.encode_to_vec()).await
        }
    }

    async fn accept_transfer(&mut self) -> Result<(), anyhow::Error> {
        let ids: Vec<i64> = self.state.transferred_files.keys().copied().collect();

        for id in ids {
            let mfi = self.state.transferred_files.get_mut(&id)
                .ok_or_else(|| anyhow!("Missing transferred_file entry"))?;

            let file = File::create(&mfi.file_url)?;
            info!("Created file: {:?}", &file);
            mfi.file = Some(file);
        }

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sharing_nearby::connection_response_frame::Status::Accept.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        self.update_state(
            |e| {
                e.state = TransferState::ReceivingFiles;
            },
            true,
        )
        .await;

        Ok(())
    }

    async fn reject_transfer(
        &mut self,
        reason: Option<sharing_nearby::connection_response_frame::Status>,
    ) -> Result<(), anyhow::Error> {
        let sreason = if let Some(r) = reason {
            r
        } else {
            sharing_nearby::connection_response_frame::Status::Reject
        };

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sreason.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        Ok(())
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
            .ok_or_else(|| anyhow!("Invalid peer public key"))?;
        let priv_key = self.state.private_key.as_ref()
            .ok_or_else(|| anyhow!("Missing private_key"))?;

        let dhs = diffie_hellman(priv_key.to_nonzero_scalar(), peer_key.as_affine());
        let derived_secret = Sha256::digest(dhs.raw_secret_bytes());

        let client_init = self.state.client_init_msg_data.as_ref()
            .ok_or_else(|| anyhow!("Missing client_init_msg_data"))?;
        let server_init = self.state.server_init_data.as_ref()
            .ok_or_else(|| anyhow!("Missing server_init_data"))?;
        let mut ukey_info: Vec<u8> = vec![];
        ukey_info.extend_from_slice(client_init);
        ukey_info.extend_from_slice(server_init);

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
                e.decrypt_key = Some(client_key);
                e.recv_hmac_key = Some(client_hmac_key);
                e.encrypt_key = Some(server_key);
                e.send_hmac_key = Some(server_hmac_key);
                e.pin_code = Some(to_four_digit_string(&auth_string));
                e.encryption_done = true;
            },
            false,
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

        let key = self.state.encrypt_key.as_ref()
            .ok_or_else(|| anyhow!("Missing encrypt_key"))?;
        let msg_data = d2d_msg.encode_to_vec();
        let iv = gen_random(16);

        let key_bytes: &[u8; AES_256_KEY_LEN] = key[..AES_256_KEY_LEN].try_into()
            .map_err(|_| anyhow!("Invalid encrypt_key length"))?;
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

        let send_hmac_key = self.state.send_hmac_key.as_ref()
            .ok_or_else(|| anyhow!("Missing send_hmac_key"))?;
        let mut hmac = HmacSha256::new_from_slice(send_hmac_key)?;
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

        trace!("Sending msg into the channel");
        drop(self.sender.send(ChannelMessage {
            id: self.state.id.clone(),
            msg: channel::Message::Client(MessageClient {
                kind: TransferKind::Inbound,
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
