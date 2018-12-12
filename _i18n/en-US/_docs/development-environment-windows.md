## (Recommended) VirtualBox Guest Configuration

Conducting Windows-Based Engine development inside of a VirtualBox Guest is the only fully-supported configuration at this time.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    The recommendations presented here are hard-won.
    We strongly recommend that you test using the exact parameters presented here.
    Using any other configuration will make it difficult for us to provide you with support.
  </p>
</div>

### System Requirements

Windows-Based Engine development presents non-trivial system requirements for your development host:
* Windows 10 (we've tested with Windows 10 Pro, version 1809)
* VT-x supported and enabled in BIOS
* 16GB+ of RAM
* 4+ CPU cores
* 100GB+ disk space

We'll be using VirtualBox.
**VirtualBox must have sole ownership of your hypervisor**.
This mean you cannot run:
* Hyper-V
* Windows Credential Guard
* Windows Device Guard
* VMWare Workstation / Player
* any other product that uses hypervisor extensions

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    Nested virtualization is NOT a currently supported configuration.
  </p>
  <p>
    Instructions presented here assume your host Windows install is running on "bare metal".
    Separate instructions for developing under a hypervisor (e.g. on AWS) are coming soon!
  </p>
</div>

### Prerequisites

* [Download and Install VirtualBox](https://www.virtualbox.org/wiki/Downloads).
We've tested with VirtualBox 5.2.22.
* [Download Windows 10 Pro ISO](https://www.microsoft.com/en-us/software-download/windows10ISO).
Use the Media Creation Tool to make a .ISO image.
We've tested with Windows 10 Pro, Build 10240.


### Create a Windows Guest

Use VirtualBox to create a Windows VM using the following parameters:
* Name: `polyswarm_win`
* Type: Microsoft Windows
* Version: Windows 10 (64-bit)
* RAM: 4GB+
* CPU: 2+ cores
* video memory: 128MB
* disk space: 50GB+

Use the default setting for all other options.
In particular, **do NOT enable 3D acceleration**.


### Install Windows 10

Use the ISO you downloaded to install Windows in the VM.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    Conducting Windows updates in a VirtualBox VM is not recommended and is quite likely to leave your VM in an un-bootable state.
    We recommend <a href="https://www.thewindowsclub.com/turn-off-windows-update-in-windows-10">disabling Windows Update</a> immediately after you install Windows in the VM.
  </p>
</div>

### (Optional) Install VirtualBox Guest Additions

Guest Additions are necessary for Shared Clipboard / Copy & Paste features between Guest and Host.

[Refer to VirtualBox's manual](https://www.virtualbox.org/manual/ch04.html).


###  Guest Creation Complete

Once Guest Additions are installed, you're ready to [Configure Windows](#configure-windows) for development inside of the VM.


## (Unsupported) Custom Configuration

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    Developing Windows-Based Engines outside of a VirtualBox virtual machine will preclude you from conducting integration tests at this time.
    We strongly recommend that you conduct development inside of a Windows VirtualBox Guest (described above) at this time.
  </p>
</div>

Minimum system requirements:
* Windows 10*
* 4+ CPU cores
* 4GB of RAM

*Older versions of Windows may work, but are untested (and unsupported) at this time.


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

2. Force PowerShell to use TLSv2 (required of some dependancies):
    
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

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    We strongly recommend disabling all anti-malware products in your development environment - including the built-in Windows Defender.
    Below, we describe disabling Windows Defender.
    Disabling third party solutions is left as an exercise for the reader.
  </p>
</div>

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


## Install `polyswarm-client` Libraries

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    If you're using a virtualenv (see above), ensure that you activate it before installing `polyswarm-client`.
  </p>
</div>

Installing `polyswarm-client` is as simple as:
```bash
pip install polyswarm-client
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

Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file.

[Make a "Hello World" Microengine →](/microengines-scratch-to-eicar/)
