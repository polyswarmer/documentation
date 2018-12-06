# Testing Windows-Based Engines


## TODO requirements

## Windows VM configuration (`polyswarm_win`):
* Windows 10 Pro
* 4GB RAM
* 4 CPU
* Enable PAE/NX (probably not required)
* tools installed
* video memory 128MB
* 3D acceleration off

## Linux VM configuration (`polyswarm_lin`):
* Xubuntu 18.04
* 8GB RAM
* 4 CPU
* tools installed
* video memory 128MB
* 3D acceleration off


## Unit Testing

TODO


## Integration Testing


### Establish Networking Between Your Linux & Windows VMs

We need to establish an "internal" network that our Linux and Windows VMs will use to communicate with one another.

Before we get started, shut down both the Linux and the Windows VM.

Open a PowerShell and change to the VirtualBox installation directory:
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
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> microengine --keyfile keyfile --password password --backen
d polyswarm_mywindowsengine --polyswarmd-addr polyswarmd:31337 --insecure-transport
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

