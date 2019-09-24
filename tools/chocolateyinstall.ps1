$ErrorActionPreference = 'Stop';
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

Set-Variable -Name "vd_install_dir" -Value "$env:LOCALAPPDATA\vd"

Set-Variable -Name "vd_binary" -Value "vd-verifier.exe"
Set-Variable -Name "vd_manifest" -Value "io.github.vd.json"

Set-Variable -Name "vd_manifest_path" -Value "$vd_install_dir\$vd_manifest"
Set-Variable -Name "vd_binary_path" -Value "$vd_install_dir\$vd_binary"

Get-ChocolateyUnzip -File "$toolsDir\vd-verifier.7z" -Destination $vd_install_dir

Rename-Item -Path "$vd_install_dir\io.github.vd.template.json" -NewName "$vd_manifest"
(Get-Content "$vd_manifest_path").Replace("<INSERT_PATH_HERE>", "$vd_binary_path").Replace("\", "\\") `
    | Set-Content "$vd_manifest_path"

New-Item -Path "HKCU:\Software\Mozilla\NativeMessagingHosts\" `
  -Name io.github.vd -Value "$vd_manifest_path" -Force
