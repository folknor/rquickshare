use crate::AppState;

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri requires State by value
pub fn is_ready(state: tauri::State<'_, AppState>) -> bool {
    state.sender_file.get().is_some()
}
