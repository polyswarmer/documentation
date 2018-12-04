# Windows Development Environment

## System Requirements

* x86-64 CPU
* 4GB of RAM
* Windows 10*

*Older versions of Windows may work, but are untested (and unsupported) at this time.

> Warning: These instructions will make changes to your Windows installation. 
We strongly recommend that you isolate these changes from your host system by conducting Windows development inside of a virtual machine, using e.g. VMWare, QEMU, VirtualBox, etc.


## Configure Windows

We'll need to use Administrator privilege to make several changes to default Windows settings.
We'll need an "elevated" / "privileged" PowerShell console:
- search "PowerShell" in the desktop search bar
- right click on "Windows PowerShell"
- select "Run as administrator". 

Run the following in this privileged PowerShell console.

1. Permit script execution (necessary for installing Chocolatey & using virtualenvs):

```powershell
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
```

1. Force PowerShell to use TLSv2 (required of some dependancies):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```


## Install Chocolatey & Prerequisities

Chocolatey is a package manager for Windows.
We'll use it to help with installing some prerequisites.

Run the following in a *privileged* PowerShell console.

1. Install Chocolatey:

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

2. Use Chocolatey to install prerequisites (do these one at a time):

```powershell
choco install -y python --version 3.5.4
choco install -y git
choco install -y visualcpp-build-tools --version 14.0.25420.1
```


## Disable Anti-Malware Products

> Warning: We strongly recommend disabling all anti-malware products in your development environment - including the built-in Windows Defender. Below, we describe disabling Windows Defender. Disabling third party solutions is left as an exercise for the reader.

PolySwarm engines should expect to come into contact with malware.
Existing anti-malware engines, including the built-in Windows Defender, can easily get in our way, quarantining or deleting files during development.

Disabling Windows Defender is a two step process.

1. Run the following command in a privileged PowerShell:

```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1
```

2. Reboot Windows.


### Continue Configuring Your Environment

That's a wrap for all the Windows-specific items!

[Let's regroup with Linux-based engine developers to finalize our environment ->](TODO: dev_env_common.md). 
