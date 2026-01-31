#![allow(clippy::let_underscore_must_use)] // Tauri macro generates code that triggers this

use rqs::SendInfo;

use crate::AppState;

#[tauri::command]
pub async fn send_payload(
    message: SendInfo,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    info!("send_payload: {:?}", &message);

    let sender = state
        .sender_file
        .get()
        .ok_or_else(|| "Backend not ready yet. Please wait for initialization.".to_string())?;

    sender
        .send(message)
        .await
        .map_err(|e| format!("couldn't send payload: {e}"))
}
