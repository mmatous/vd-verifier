Set-Variable -Name "vd_install_dir" -Value "$env:LOCALAPPDATA\vd"

Remove-Item "$vd_install_dir" -Force -Recurse
Remove-Item "HKCU:\Software\Mozilla\NativeMessagingHosts\io.github.vd" -Force
