!macro NSIS_HOOK_PREINSTALL
  ; stop the TUN front-end first so it removes its adapter/routes cleanly
  nsExec::Exec 'taskkill /F /IM sing-box.exe'
  nsExec::Exec 'taskkill /F /IM sing-box-arm64.exe'
  Sleep 500
  nsExec::Exec 'taskkill /F /IM xray.exe'
  nsExec::Exec 'taskkill /F /IM xray-arm64.exe'
  Sleep 500
  ; the bundled exe is productName.exe on some Tauri versions and
  ; cargo-name.exe on others - close both so an upgrade is never blocked
  nsExec::Exec 'taskkill /F /IM "LionRay VPN.exe"'
  nsExec::Exec 'taskkill /F /IM lionray-desktop.exe'
  Sleep 500
!macroend

!macro NSIS_HOOK_POSTINSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'taskkill /F /IM sing-box.exe'
  nsExec::Exec 'taskkill /F /IM sing-box-arm64.exe'
  Sleep 500
  nsExec::Exec 'taskkill /F /IM xray.exe'
  nsExec::Exec 'taskkill /F /IM xray-arm64.exe'
  Sleep 500
  nsExec::Exec 'taskkill /F /IM "LionRay VPN.exe"'
  nsExec::Exec 'taskkill /F /IM lionray-desktop.exe'
  Sleep 500
!macroend
