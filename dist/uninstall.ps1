If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

Set-Variable -Name "vd_install_dir" -Value "$env:LOCALAPPDATA\vd"

Remove-Item "$vd_install_dir" -Force -Recurse
Remove-Item "HKCU:\Software\Mozilla\NativeMessagingHosts\io.github.vd" -Force
