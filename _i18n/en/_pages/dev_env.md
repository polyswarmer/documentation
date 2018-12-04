# Developing on PolySwarm

Developers interested in building (BUIDLing) for the PolySwarm marketplace should start here!

PolySwarm supports both Linux and Windows based engines (arbiters, ambassadors & microengines).

Our Linux-based engines are fully Dockerized and our Windows-based engines are fully virtualized; the instructions presented here reflect these recommendations, but of course feel free to bundle your engine however you like.

Next: choose your adventure - is your engine Linux or Windows-based?


## Linux Environment

## Set up a Microengine Development Environment

This guide will reference and build on:
* [**polyswarm-client**](https://github.com/polyswarm/polyswarm-client): The Swiss Army knife of exemplar PolySwarm participants ("clients"). 
`polyswarm-client` can function as a `microengine` (we'll build on this functionality in this tutorial), an `arbiter` and an `ambassador` (we'll use these to test what we built).
* [**polyswarmd**](https://github.com/polyswarm/polyswarmd): The PolySwarm daemon. This daemon handles Ethereum and IPFS idiosyncrasies for you, allowing you to focus on Microengine development :)
* [**contracts**](https://github.com/polyswarm/contracts): The contracts that all Microengines must support.
* [**orchestration**](https://github.com/polyswarm/orchestration): A set of `docker-compose` files that we'll use to conveniently stand up a local test network.

### Docker

We've Docker-ized as many things as we could to make it as easy as possible to get started, regardless of your development environment.
Assuming Docker is installed, these images should *just work* under Windows, Mac OS X and Linux.
Please ensure that your system has at least 4GB of RAM available.

To get started, you'll need Docker-CE (base) as well as Docker Compose (packaged with Docker in all modern releases).
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

Once installed, verify that the installation works.

```sh
docker -v
```
Should output at least: `Docker version 18.05.0-ce build f150324`

```sh
$ docker-compose -v
```
Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`

### Git

We'll need to grab a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.

### Grab the Code

```sh
git clone https://github.com/polyswarm/polyswarm-client
git clone https://github.com/polyswarm/orchestration
```


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

1. Permit script execution (necessary for installing Chocolatey & using virtualenvs):

```
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
```

1. Force PowerShell to use TLSv2 (required of some dependancies):

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```


### Install Chocolatey & Prerequisities

Chocolatey is a package manager for Windows.
We'll use it to help with installing some prerequisites.

Run the following in a *privileged* PowerShell console.

1. Install Chocolatey:

```
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

2. Use Chocolatey to install prerequisites (do these one at a time):

```
choco install -y python --version 3.5.4
choco install -y git
choco install -y visualcpp-build-tools --version 14.0.25420.1
```

# TODO: they need to open a new shell to get python - do that with permitting scripts

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

Issue the following in a *non-privileged* PowerShell:

```
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

We will now use this activated PowerShell to run our python commands.

Once in the virtualenv, install `polyswarm-client` libraries:
```
pip install git+https://github.com/polyswarm/polyswarm-client.git#egg=polyswarm-client
```


## Wrapping Up

You're now all set to dive into PolySwarm development!

In the next section, we'll walk you through building your very own PolySwarm microengine, capable of detecting the EICAR test file.


TODO: orchestration, local windows testing
