use rqs::channel::ChannelMessage;

use crate::AppState;

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri requires State by value
pub fn send_to_rs(
    message: ChannelMessage,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    info!("send_to_rs: {:?}", &message);

    match state.message_sender.send(message) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Coudln't perform: {e}")),
    }
}
