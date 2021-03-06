If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

Set-Location -Path $PSScriptRoot
Set-Variable -Name "vd_manifest_dir" -Value "$env:LOCALAPPDATA\vd"
Set-Variable -Name "vd_binary_dir" -Value "$env:ProgramFiles\vd"

Set-Variable -Name "vd_binary" -Value "vd-verifier.exe"
Set-Variable -Name "vd_manifest" -Value "io.github.vd.json"

Set-Variable -Name "vd_manifest_path" -Value "$vd_manifest_dir\$vd_manifest"
Set-Variable -Name "vd_binary_path" -Value "$vd_binary_dir\$vd_binary"

New-Item -p "$vd_manifest_dir", "$vd_binary_dir" -ItemType "directory" -Force
Copy-Item io.github.vd.template.json -Destination "$vd_manifest_path" -Force
Copy-Item "$vd_binary" -Destination "$vd_binary_dir" -Force
Copy-Item uninstall.ps1 -Destination "$vd_binary_dir" -Force
(Get-Content "$vd_manifest_path").Replace("<INSERT_PATH_HERE>", "$vd_binary_path").Replace("\", "\\") `
    | Set-Content "$vd_manifest_path"

Set-Location HKCU:
New-Item -Path ".\Software\Mozilla\NativeMessagingHosts\" `
    -Name io.github.vd -Value "$vd_manifest_path" -Force
