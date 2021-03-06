If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

Set-Variable -Name "vd_manifest_dir" -Value "$env:LOCALAPPDATA\vd"
Set-Variable -Name "vd_binary_dir" -Value "$env:ProgramFiles\vd"

Remove-Item "$vd_manifest_dir" -Force -Recurse
Remove-Item "$vd_binary_dir" -Force -Recurse
Set-Location HKCU:
Remove-Item ".\Software\Mozilla\NativeMessagingHosts\io.github.vd" -Force
