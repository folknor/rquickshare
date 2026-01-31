//! Simple CLI for debugging RQS without the Tauri GUI

use rqs::channel::{ChannelMessage, Message, TransferAction};
use rqs::hdl::TransferState;
use rqs::RQS;
use tokio::signal;
use tokio::sync::broadcast::Sender;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    println!("Starting RQS debug server (AUTO-ACCEPT MODE)...");

    let mut rqs = RQS::default();

    // Subscribe to messages before running
    let receiver = rqs.message_sender.subscribe();
    let sender = rqs.message_sender.clone();

    // Start the service
    let (_sender_file, _ble_receiver) = rqs.run().await?;

    println!("RQS server running. Press Ctrl+C to stop.");
    println!("All incoming transfers will be AUTO-ACCEPTED.\n");

    // Spawn a task to print all channel messages and auto-accept
    tokio::spawn(async move {
        handle_messages(receiver, sender).await;
    });

    // Wait for Ctrl+C
    signal::ctrl_c().await?;

    println!("\nShutting down...");
    rqs.stop().await;

    Ok(())
}

async fn handle_messages(
    mut receiver: tokio::sync::broadcast::Receiver<ChannelMessage>,
    sender: Sender<ChannelMessage>,
) {
    loop {
        match receiver.recv().await {
            Ok(msg) => {
                println!(">>> ChannelMessage: {msg:?}");

                // Auto-accept when we reach WaitingForUserConsent
                if let Message::Client(ref client) = msg.msg
                    && client.state == Some(TransferState::WaitingForUserConsent)
                {
                    println!("==> AUTO-ACCEPTING transfer from {}", msg.id);
                    let accept_msg = ChannelMessage {
                        id: msg.id.clone(),
                        msg: Message::Lib {
                            action: TransferAction::ConsentAccept,
                        },
                    };
                    if let Err(e) = sender.send(accept_msg) {
                        eprintln!("Failed to send accept: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Receiver error: {e}");
                break;
            }
        }
    }
}
