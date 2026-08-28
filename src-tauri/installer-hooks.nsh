!macro NSIS_HOOK_PREINSTALL
  nsExec::Exec 'taskkill /F /IM xray.exe'
  Sleep 500
  nsExec::Exec 'taskkill /F /IM lionray-desktop.exe'
  Sleep 500
!macroend

!macro NSIS_HOOK_POSTINSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'taskkill /F /IM xray.exe'
  Sleep 500
  nsExec::Exec 'taskkill /F /IM lionray-desktop.exe'
  Sleep 500
!macroend
