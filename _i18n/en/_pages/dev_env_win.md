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


## (Optional) Set up a Virtual Environment (virtualenv)

If you plan to use this Windows installation for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

> Info: If you install `polyswarm-client` in a virtualenv, you'll need to "activate" the virtualenv (see above) each time you open a shell.


## Install `polyswarm-client` Libraries

> Info: If you're using a virtualenv, ensure that you activate it before installing `polyswarm-client`.

Installing `polyswarm-client` is as simple as:
```bash
pip install git+https://github.com/polyswarm/polyswarm-client.git#egg=polyswarm-client
```


## Verify Installation

You should now have a working development environment!

To verify, simply try importing `polyswarmclient`:
```bash
$ python
Python 3.5.4 (v3.5.4:3f56838, Aug  8 2017, 02:17:05) [MSC v.1900 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import polyswarmclient
>>>
```

You should be able to import `polyswarmclient` without issue.

[Next, we'll walk you through building your very own PolySwarm microengine, capable of detecting the EICAR test file ->](TODO: link to tut-eicar.md)

TODO:

# Creating a Windows Engine

Docker on Windows leaves a lot to be desired, so instead we use [Packer](https://www.packer.io/) to build Windows-based [AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html).

Windows-based engines are built in 2 stages:
1. We build a skeleton Windows AMI with Python on [Windows builds of `polyswarm-client` libraries installed](https://github.com/polyswarm/polyswarm-client).
2. `cookiecutter` produces a template microengine wrap project that contains a Packer template and Continuous Integration (CI) instructions to build & push the resultant AMI.

