# Testing Windows-Based Engines

These instructions will enable you to perform local testing of your Windows-based microengine.
The first step is to create one Windows and one Linux VM.
The Windows VM is where you will run your Windows-based microengine (and possibily do your development).
And the Linux VM is where you will run a local testing version of the PolySwarm marketplace, which we'll call the "testnet".
The next step is to network the two VMs together and configure them.
Finally, you can perform your local testing.

## TODO requirements

These instructions assume that you have a recent Windows desktop or server computer that meets the following requirements:
* VT-X enabled in BIOS, to enable you to run VMs
* More than 8GB of RAM
* More than 8 64bit CPU cores
* At least 100GB of available disk space

We've tested the instructions on a Windows 10 Pro desktop.

* [Download and Install VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* [Download Windows 10 Pro ISO](https://www.microsoft.com/en-us/software-download/windows10ISO)
* [Download Xubuntu 18.04 amd64 ISO](https://xubuntu.org/release/18-04/)

## Windows VM configuration (`polyswarm_win`):

> Note: If you are already doing your development in a Windows VM, you do not need to create an additional Windows VM for testing.
You simply substitute your Windows VM name for `polyswarm_win` in our instructions in this document.

Create a Windows VM using the following parameters:

* Name: polyswarm_win
* Windows 10 Pro
* 4GB RAM
* 4 CPU
* Enable PAE/NX (probably not required)
* tools installed
* video memory 128MB
* 3D acceleration off
* TODO: size of disk

## Linux VM configuration (`polyswarm_lin`):

Create a Linux VM using the following paramters:

* Name: polyswarm_lin
* Xubuntu 18.04 amd64
* 8GB RAM
* 4 CPU
* tools installed
* video memory 128MB
* 3D acceleration off
* TODO: size of disk

## Configure VMs for PolySwarm testing

### Establish Networking Between Your Linux & Windows VMs

We need to establish an "internal" network that our Linux and Windows VMs will use to communicate with one another.

Before we get started, shut down both the Linux and the Windows VM.

On your host computer, open a PowerShell and change to the VirtualBox installation directory:
```powershell
PS C:\Users\user> pushd $Env:Programfiles\Oracle\VirtualBox
PS C:\Program Files\Oracle\VirtualBox>
```

#### Create Internal PolySwarm Network

Create and assign a dedicated PolySwarm internal network to each VM.

> Warning: these commands will reconfigure network adapter #5 on your VMs.
If you are already using this adapter (unlikely), change the number in the commands.

```powershell
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_win" --nic5 intnet
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_win" --intnet5 "polyswarm_net"
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_lin" --nic5 intnet
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_lin" --intnet5 "polyswarm_net"
```

> Info: for more information on internal networking in VirtualBox, refer to their [official documentation](https://www.virtualbox.org/manual/ch06.html#network_internal)


#### Configure VMs with Static IPs

Boot `polyswarm_lin` and assign the following static IPv4 information to the new adapter:
* address: `192.168.0.101`
* netmask: `255.255.255.0`
* gateway: `192.168.0.1`

Boot `polyswarm_win` and configure the new adapter for these static IPv4 settings:
* address: `192.168.0.102`
* netmask: `255.255.255.0`
* gateway: `192.168.0.1`

TODO: why does the windows VM need a static IP? This seems like an unnecessary step.
TODO: we should use a network that is less common with people's home routers/lans to prevent conflicts. How about 192.168.42.0/24?

#### Configure Windows VM for `polyswarmd` DNS Resolution

Finally, your Windows VM needs to know that your Linux VM is hosting `polyswarmd`.
Open an elevated instance of Notepad and add `polyswarmd` to the bottom of `C:\Windows\System32\Drivers\etc`:
```
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost

192.168.0.101 polyswarmd
```

#### Verify Configuration

Finally, verify that Windows resolves `polyswarmd` to your Linux VM and is able to reach the VM:
```powershell
PS C:\Users\user> Resolve-DnsName -name polyswarmd

Name                                           Type   TTL   Section    IPAddress
----                                           ----   ---   -------    ---------
polyswarmd                                     A      86400 Answer     192.168.0.101

PS C:\Users\user> ping polyswarmd

Pinging polyswarmd [192.168.0.101] with 32 bytes of data:
Reply from 192.168.0.101: bytes=32 time<1ms TTL=64
```

Looking good!

### Install tools on Linux VM

There are some tools we need to install on the Linux VM to enable it to act as a testnet.

#### Install Docker

We've Docker-ized the test version of the PolySwarm marketplace.
To use it, you need to install Docker-CE (base) as well as Docker Compose.
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

Once installed, verify that the installation works.

```bash
docker -v
```

Should output at least: `Docker version 18.05.0-ce build f150324`

Also install [`docker-compose`](https://docs.docker.com/compose/install/)

```bash
$ docker-compose -v
```

Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`

> Note: If you get permission errors when running docker or docker-compose commands, prefix the command with `sudo`.

#### Download polyswarm/orchestration

On github, we publish the `polyswarm/orchestration` project to enable developers to run a local testing version of the PolySwarm marketplace.
Open a browser in the Linux VM and browse to the [polyswarm/orchestration](https://github.com/polyswarm/orchestration) project.
On that page, click on the green button and select `Download ZIP`.
Once you've downloaded the .zip file, extract it to your home directory.
That will create a directory named `orchestration-master` in your home directory.
Any docker commands you run when testing your microengine must be run from within this `orchestration-master` directory.

### Install tools on Windows VM

Your Windows VM can be your main development environment if you choose to do so.
But regardless, it will need to be setup following the instructions for [Setting up a Windows Development Environment]()TODO: insert link to development-environment-windows.md.
And then you'll need to copy your microengine project directory into the VM to do testing.

## Unit Testing

TODO


## Integration Testing


### Test Your Engine

#### Start the Testnet

Using your Linux VM, spin up a subset of the testnet, leaving out the stock `microengine` (we'll be replacing this with our own) and the `ambassador` services:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

It will take several minutes for `polyswarmd` to become available.
Once `polyswarmd` is available, it will begin serving responses to clients, e.g.:
```
INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
```

On your Windows VM, confirm that `polyswarmd` is available and ready to respond to your microengine:
```
PS C:\Users\user> curl -UseBasicParsing http://polyswarmd:31337/status


StatusCode        : 200
StatusDescription : OK
Content           : {"result":{"home":{"block":189,"reachable":true,"syncing":false},"ipfs":{"reachable":true},"side":{
                    "block":191,"reachable":true,"syncing":false}},"status":"OK"}
...
```

The key thing to look for is `"status":"OK"`.

#### Start Your Windows-Based Engine

TODO

```powershell
(cd into microengine dr)
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> pip install -r requirements.txt
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> pip install .
(TODO make a keyfile)
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> microengine --keyfile keyfile --password password --backend polyswarm_mywindowsengine --polyswarmd-addr polyswarmd:31337 --insecure-transport --testing 2
```

this means we're ready for some artifacts:
```powershell
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> microengine --keyfile keyfile --password password --backend polyswarm_mywindowsengine --polyswarmd-addr polyswarmd:31337 --insecure-transport
INFO:root:2018-12-05 22:15:29,256 Logging in text format.
INFO:polyswarmclient:2018-12-05 22:15:29,880 Using account: 0x34E583cf9C1789c3141538EeC77D9F0B8F7E89f2
INFO:polyswarm_mywindowsengine:2018-12-05 22:15:29,880 Loading MyWindowsEngine scanner...
INFO:polyswarmclient:2018-12-05 22:15:30,240 Received connected on chain side: {'start_time': '1544074923.6622703'}
INFO:root:2018-12-05 22:15:30,240 Connected to event socket at: 1544074923.6622703
INFO:polyswarmclient:2018-12-05 22:15:31,224 Received block on chain side: {'number': 2079}
INFO:polyswarmclient:2018-12-05 22:15:32,255 Received block on chain side: {'number': 2080}
...
```

Back in Linux VM, let's give it some artifacts:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Take a look at Windows output:
```powershell
INFO:polyswarmclient:2018-12-05 22:20:24,896 Received bounty on chain side: {'amount': '62500000000000000', 'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'guid': 'e01f222b-d9de-44cb-9780-f3ddef2dd0e7', 'expiration': '2393', 'uri': 'QmVjWbqv8aXEPE53vDYS9r3wG7odJjrHXf7ci1xfLyNAEU'}
INFO:polyswarmclient.abstractmicroengine:2018-12-05 22:20:24,896 Testing mode, 1 bounties remaining
```

TODO: balancemanager

