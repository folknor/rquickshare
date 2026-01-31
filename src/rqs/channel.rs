use serde::{Deserialize, Serialize};

use crate::{TransferState, hdl::info::TransferMetadata};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransferAction {
    ConsentAccept,
    ConsentDecline,
    TransferCancel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransferKind {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageClient {
    pub kind: TransferKind,
    pub state: Option<TransferState>,
    pub metadata: Option<TransferMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Lib { action: TransferAction },
    Client(MessageClient),
}

impl Message {
    pub fn as_client(&self) -> Option<&MessageClient> {
        match self {
            Message::Client(message_client) => Some(message_client),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMessage {
    pub id: String,
    pub msg: Message,
}
