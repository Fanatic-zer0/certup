mod cert;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![
      cert::cert_verify_chain,
      cert::cert_match_key,
      cert::cert_match_csr,
      cert::cert_generate_csr,
      cert::cert_generate,
      cert::cert_to_pkcs12,
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
