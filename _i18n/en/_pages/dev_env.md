# Developing for PolySwarm

Developers interested in building (BUIDLing) for the PolySwarm marketplace should start here!

PolySwarm supports both Linux and Windows based engines (arbiters, ambassadors & microengines).

Our Linux-based engines are fully Dockerized and our Windows-based engines are fully virtualized; the instructions presented here reflect these recommendations, but of course feel free to bundle your engine howevery you like.

Next: choose your adventure - is your engine Linux or Windows-based?


## Linux Environment

TODO


## Windows Environment

> Note: These instructions have been tested on Windows 10, but should work on prior Windows versions with slight variation.

> Note: These instructions will make changes to your Windows installation. We strongly recommend that you isolate these changes from your host system by conducting Windows development inside of a virtual machine, using e.g. VMWare, QEMU, VirtualBox, etc.

> Note: These instructions produce AMI files for use on Amazon AWS. Stay tuned for instructions supporting other hosting providers and local hosting options.


### Configure Windows

We'll need to make changes to several default Windows settings.
For this, we'll need an "elevated" / "privileged" PowerShell console:
- search "PowerShell" in the desktop search bar
- right click on "Windows PowerShell"
- select "Run as administrator". 

Run the following in this privileged PowerShell console.

1. Permit script execution (necessary for installing Chocolatey):

```
Set-ExecutionPolicy Bypass -Scope Process -Force
```

1. Force PowerShell to use TLSv2 (required of some dependancies):

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

1. Create & change to a local directory for housing installation files:

```
mkdir ~/installers
pushd ~/installers
```

Finally, we'll need to permit scripting in a non-privileged context as well, so open a non-privileged PowerShell window and run this again:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### Install Chocolatey & Prerequisities

Chocolatey is a package manager for Windows.
We'll use it to help with installing some prerequisites.

Run the following in a privileged PowerShell console.

1. Install Chocolatey:

```
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

2. Use Chocolatey to install prerequisites (do these one at a time):

```
choco install python --version 3.5.4 -y
choco install git -y
choco install 7zip -y
choco install visualcpp-build-tools --version 14.0.25420.1 -y
choco install vim -y
```

### Disable Anti-Malware Products

> Note: We strongly recommend disabling all anti-malware products in your development environment - including the built-in Windows Defender. Below, we describe disabling Windows Defender. Disabling third party solutions is left as an exercise to the user.

PolySwarm engines should expect to come into contact with malware.
Existing anti-malware engines, including the built-in Windows Defender, can easily get in our way, quarantining or deleting files during development.

Disabling Windows Defender is a two step process.

1. Run the following command in a privileged PowerShell:

```
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1
```

2. Reboot Windows.


### Create Python Virtual Environment

We will create a Python virtual environment (virtualenv), so we avoid dirtying system-wide Python packages.

Issue the following in a non-privileged PowerShell:

```
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

We will now use this activated PowerShell to run our python commands.


### Grab `polyswarm-client`

The easiest way to get going on building a PolySwarm engine is to build on our `polyswarm-client`.

We're done with the elevated PowerShell - close this PowerShell and open a new (not elevated) PowerShell.

Run the following command in the non-privileged PowerShell:

```
git clone https://github.com/polyswarm/polyswarm-client.git
```

### Install Python Packages (in the Virtual Environment)

1. Ensure you're in your PolySwarm virtualenv (from previous step).

2. Install prerequisites:
```
cd polyswarm-client
pip install --upgrade awscli
pip install -r requirements.txt
pip install .
```

> Note: Don't forget the '.' after the word install in the final command.

The last pip command above will install the polyswarm-client python package into your virtual environment.


## Wrapping Up

You're now all set to dive into PolySwarm development!

In the next section, we'll walk you through building your very own PolySwarm microengine, capable of detecting the EICAR test file.
