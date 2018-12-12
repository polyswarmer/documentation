# Testing Windows-Based Engines


## Unit Testing

`tox` runs whatever unit tests you add to `src/scan_test.py`.
We'll use `tox` to test our Microengine:
```powershell
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> tox
GLOB sdist-make: C:\Users\user\microengine-mywindowsengine\setup.py
py35 create: C:\Users\user\microengine-mywindowsengine\.tox\py35
py35 installdeps: -rrequirements.txt
py35 inst: C:\Users\user\microengine-mywindowsengine\.tox\dist\polyswarm_mywindowsengine-0.1.zip
py35 installed: aiodns==1.1.1,aiohttp==2.3.1,aioresponses==0.5.0,async-generator==1.10,async-timeout==3.0.1,asynctest==0.12.2,atomicwrites==1.2.1,attrdict==2.0.0,attrs==18.2.0,base58==0.2.5,certifi==2018.11.29,chardet==3.0.4,clamd==1.0.2,click==6.7,colorama==0.4.1,coverage==4.5.1,cytoolz==0.9.0.1,eth-abi==1.3.0,eth-account==0.3.0,eth-hash==0.2.0,eth-keyfile==0.5.1,eth-keys==0.2.0b3,eth-rlp==0.1.2,eth-typing==2.0.0,eth-utils==1.4.0,hexbytes==0.1.0,hypothesis==3.82.1,idna==2.7,lru-dict==1.1.6,malwarerepoclient==0.1,more-itertools==4.3.0,multidict==4.5.2,parsimonious==0.8.1,pathlib2==2.3.3,pluggy==0.8.0,polyswarm-client==0.2.0,polyswarm-mywindowsengine==0.1,py==1.7.0,pycares==2.3.0,pycryptodome==3.7.2,pypiwin32==223,pytest==3.9.2,pytest-asyncio==0.9.0,pytest-cov==2.6.0,pytest-timeout==1.3.2,python-json-logger==0.1.9,python-magic==0.4.15,pywin32==224,requests==2.19.1,rlp==1.0.3,six==1.11.0,toml==0.10.0,toolz==0.9.0,tox==3.4.0,urllib3==1.23,virtualenv==16.1.0,web3==4.6.0,websockets==6.0,yara-python==3.7.0,yarl==1.2.6
py35 run-test-pre: PYTHONHASHSEED='432'
py35 runtests: commands[0] | pytest -s
================================================= test session starts =================================================
platform win32 -- Python 3.5.4, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('C:\\Users\\user\\microengine-mywindowsengine\\.hypothesis\\examples')
rootdir: C:\Users\user\microengine-mywindowsengine, inifile:
plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
collected 1 item

src\polyswarm_mywindowsengine\scan_test.py .

================================================== warnings summary ===================================================
c:\users\user\microengine-mywindowsengine\.tox\py35\lib\site-packages\eth_utils\applicators.py:32: DeprecationWarning: combine_argument_formatters(formatter1, formatter2)([item1, item2])has been deprecated and will be removed in a subsequent major version release of the eth-utils library. Update your calls to use apply_formatters_to_sequence([formatter1, formatter2], [item1, item2]) instead.
  "combine_argument_formatters(formatter1, formatter2)([item1, item2])"

-- Docs: https://docs.pytest.org/en/latest/warnings.html
======================================== 1 passed, 1 warnings in 0.52 seconds =========================================
_______________________________________________________ summary _______________________________________________________
  py35: commands succeeded
  congratulations :)
```

You can safely ignore the `combine_argument_formatters` warning.


## (Local) Integration Testing

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    Conducting integration tests on Windows-Based Engines is only supported in a VirtualBox configuration at this time.
    Please refer to <a href="/development-environment-windows/">Windows Development Environment</a> for more information.
  </p>
</div>

Integration testing a Windows-Based Engine requires two virtual machines (VMs / Guests):
1. A Windows guest for running your Windows-Based engine (we already made this).
1. A Linux guest for standing up a local PolySwarm testnet (we'll make this now).

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    The recommendations presented here are hard-won.
    We strongly recommend that you test using the exact recommendations presented here.
    Using any other configuration will make it difficult for us to provide you with support.
  </p>
</div>

### Create a Linux Guest


#### Create the Virtual Machine

Create a Linux VM using the following parameters:
* Name: `polyswarm_lin`
* Type: Linux
* Version: Ubuntu (64-bit)
* RAM: 8GB+
* CPU: 4+ cores
* video memory: 128MB
* disk space: 50GB+

Use the default setting for all other options.
In particular, do NOT enable 3D acceleration.

In general, you will want to provide extra available RAM and CPU resources to the linux VM to make the testnet perform better.

#### Install Xubuntu 18.04 amd64

* [Download Xubuntu 18.04 amd64 ISO](https://xubuntu.org/release/18-04/)

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    We strongly recommend Xubuntu over Ubuntu for VirtualBox guests.
    Ubuntu presents a range of visual lag issues and is prone to total visual lockup when VirtualBox tools are installed.
  </p>
</div>

Use the ISO you downloaded to install Xubuntu in the VM.


#### (Optional) Install VirtualBox Guest Additions

Guest Additions are necessary for Shared Clipboard / Copy & Paste features between Guest and Host.

[Refer to VirtualBox's manual](https://www.virtualbox.org/manual/ch04.html).


### Configure Inter-Guest Networking

We need to establish an "internal" network that our Linux and Windows VMs will use to communicate with one another.

Before we get started, shut down both the Linux and the Windows Guests.

On your Host, open a PowerShell and change to the VirtualBox installation directory:
```powershell
PS C:\Users\user> pushd $Env:Programfiles\Oracle\VirtualBox
PS C:\Program Files\Oracle\VirtualBox>
```

#### Create Internal PolySwarm Network

Create and assign a dedicated PolySwarm internal network to each VM.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    These commands will reconfigure network adapter #5 on your VMs.
    If you are already using this adapter (very unlikely), change the number in the commands.
  </p>
</div>

```powershell
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_win" --nic5 intnet
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_win" --intnet5 "polyswarm_net"
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_lin" --nic5 intnet
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe modifyvm "polyswarm_lin" --intnet5 "polyswarm_net"
```

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    For more information on internal networking in VirtualBox, refer to their <a href="https://www.virtualbox.org/manual/ch06.html#network_internal">official documentation</a>.
  </p>
</div>

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    You will not see an "adapter #5" listed in your VM settings or inside your VM.
    What you will see is that your VM will have at least 2 active network adapters and by
    adding "polyswarm_net" to adapter 5, it should be easier to find because it will be the
    highest numbered network interface in your VM.
  </p>
</div>

#### Configure VMs with Static IPs

Boot `polyswarm_lin` and assign the following static IPv4 information to the new adapter:
* address: `10.10.42.101`
* netmask: `255.255.255.0`
* gateway: `10.10.42.1`

If it is unclear which network interface you should apply these settings to, run the `ifconfig -a`
command, and in the output you should see multiple network interfaces that start with `enp0s`.
The interface with the largest number after that prefix is usually the one you want to modify.

Boot `polyswarm_win` and configure the new adapter for these static IPv4 settings:
* address: `10.10.42.102`
* netmask: `255.255.255.0`
* gateway: `10.10.42.1`

If it is unclear which network interface you should apply these settings to, run the `ipconfig /all`
command, and in the output you should see multiple network interfaces that start with `Ethernet adapter Ethernet`.
The interface with the largest number after that prefix is usually the one you want to modify.

#### Configure Windows VM for `polyswarmd` DNS Resolution

Finally, your Windows VM needs to know that your Linux VM is hosting `polyswarmd`.
Open an elevated instance of Notepad and add `polyswarmd` to the bottom of `C:\Windows\System32\Drivers\etc\hosts`:
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

10.10.42.101 polyswarmd
```

#### Verify Configuration

Finally, verify that Windows resolves `polyswarmd` to your Linux VM and is able to reach the VM:
```powershell
PS C:\Users\user> Resolve-DnsName -name polyswarmd

Name                                           Type   TTL   Section    IPAddress
----                                           ----   ---   -------    ---------
polyswarmd                                     A      86400 Answer     10.10.42.101

PS C:\Users\user> ping polyswarmd

Pinging polyswarmd [10.10.42.101] with 32 bytes of data:
Reply from 10.10.42.101: bytes=32 time<1ms TTL=64
```

Looking good!


### Configure Linux VM for Hosting a Local Testnet

#### Install Docker

We've Docker-ized the test version of the PolySwarm marketplace.
To use it, you need to install Docker-CE (base) as well as Docker Compose.
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

On Xubuntu:
```bash
sudo apt update && sudo apt install -y curl
curl -fsSL https://get.docker.com -o get-docker.sh
chmod +x get-docker.sh
./get-docker.sh
sudo usermod -aG docker $USER
```

Log out, log back in.

Once installed, verify that the installation works.

```bash
docker -v
```

Should output at least: `Docker version 18.05.0-ce build f150324`

Also install [`docker-compose`](https://docs.docker.com/compose/install/)

On Xubuntu:
```bash
curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o docker-compose
sudo mv docker-compose /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

Once installed, verify that the installation works.

```bash
docker-compose -v
```

Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    If you receive permission errors when running docker or docker-compose commands, <a href="https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user">configure your user account for docker permission</a>.
  </p>
</div>


#### Install Git

We'll need to grab a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.

On Xubuntu 18.04:
```bash
sudo apt update && sudo apt install -y git
```

#### Download `orchestration`

We'll use the PolySwarm [`orchestration`](https://github.com/polyswarm/orchestration) project to launch our development testnet.
We use this same project internally to conduct end-to-end (integration) tests.

Clone `orchestration`:
```bash
git clone https://github.com/polyswarm/orchestration
```


### Test Your Engine

We're going to have to switch between our VMs a little bit here.
We will first start the Testnet in the Linux VM.
Then we will start your microengine in the Windows VM.
Finally, we will start the Ambassador in the Linux VM.

#### Linux VM: Launch the Testnet

In your Linux VM, spin up a subset of the testnet, leaving out the stock `microengine` (we'll be substituting this with our own) and leaving out the `ambassador` for now (we'll start it later):
```bash
cd orchestration
docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

It will take several minutes for `polyswarmd` to become available.
During this time, you will see many messages like `Problem with dial... dial tcp connection refused.` and `chain for config not available in consul yet`.
These errors are normal while the testnet is initializing, so have patience.

Once `polyswarmd` is available, it will begin serving responses to clients, e.g.:
```
INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
```

Now it is safe to move to the next step.

#### Windows VM: Test Connection to `polyswarmd`
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


#### Windows VM: Launch `balancemanager` & Your Engine

In your Microengine's directory, install your Microengine's prerequisites and your Microengine itself
```powershell
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> pip install -r requirements.txt
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> pip install .
```

`balancemanager` is a utility (based on `polyswarm-client`) that will help us maintain a balance of (fake) PolySwarm Nectar (NCT) on the sidechain of our local testnet where all transactions will take place.

Launch `balancemanager`:
```powershell
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> balancemanager maintain --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport 100000 500000
INFO:root:2018-12-06 16:55:30,800 Logging in text format.
INFO:balancemanager.__main__:2018-12-06 16:55:30,815 Maintaining the minimum balance by depositing 500000.0 when it falls below 100000.0
INFO:polyswarmclient:2018-12-06 16:55:31,440 Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:polyswarmclient:2018-12-06 16:55:32,050 Received connected on chain home: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:55:32,050 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:55:32,050 Received block on chain home: {'number': 18182}
INFO:polyswarmclient:2018-12-06 16:55:32,096 Received connected on chain side: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:55:32,096 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:55:33,034 Received block on chain home: {'number': 18183}
INFO:polyswarmclient:2018-12-06 16:55:33,080 Received block on chain side: {'number': 18206}
```

When it starts printing `Received block on chain` messages, we're ready to launch our Engine.

Run your Microengine.
To do this, you will need to start another PowerShell and activate the virtual environment.
Be sure to update the value for the `--backend` argument to match the name of your microengine's package directory (i.e. the directory in `src/`):
```powershell
(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine> microengine --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport --testing 2 --backend acme_myeicarengine
INFO:root:2018-12-06 16:56:20,674 Logging in text format.
INFO:polyswarmclient:2018-12-06 16:56:21,299 Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:polyswarmclient:2018-12-06 16:56:21,690 Received connected on chain side: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:56:21,690 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:56:22,691 Received block on chain side: {'number': 18255}
...
INFO:polyswarmclient:2018-12-06 16:56:44,205 Received block on chain side: {'number': 18277}
INFO:polyswarmclient:2018-12-06 16:56:44,283 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18297', 'uri': 'QmVoLQJ2nm4V6XiZXC9vEUrCaTHdkXS7y3crztZ5HwC9iK', 'guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'amount': '62500000000000000'}
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:44,283 Testing mode, 1 bounties remaining
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:44,455 Responding to bounty: 48dd5360-47a3-4e12-a975-eb30fed5cc22
INFO:polyswarmclient:2018-12-06 16:56:45,237 Received block on chain side: {'number': 18278}
INFO:polyswarmclient:2018-12-06 16:56:46,393 Received block on chain side: {'number': 18279}
INFO:polyswarmclient.events:2018-12-06 16:56:46,440 OnNewBountyCallback callback results: [[{'bounty_guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'mask': [True], 'bid': '62500000000000000', 'commitment': '44296088244268214239924675885675264686302131561550908677050134822720003742540', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}]]
INFO:polyswarmclient:2018-12-06 16:56:46,456 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18299', 'uri': 'QmVjWbqv8aXEPE53vDYS9r3wG7odJjrHXf7ci1xfLyNAEU', 'guid': '40862925-3e00-41b2-a946-365135d87070', 'amount': '62500000000000000'}
INFO:polyswarmclient:2018-12-06 16:56:46,456 Received assertion on chain side: {'bounty_guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'mask': [True], 'bid': '62500000000000000', 'commitment': '44296088244268214239924675885675264686302131561550908677050134822720003742540', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:46,456 Testing mode, 0 bounties remaining
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:46,643 Responding to bounty: 40862925-3e00-41b2-a946-365135d87070
INFO:polyswarmclient:2018-12-06 16:56:47,409 Received block on chain side: {'number': 18280}
INFO:polyswarmclient.events:2018-12-06 16:56:48,222 OnNewBountyCallback callback results: [[{'bounty_guid': '40862925-3e00-41b2-a946-365135d87070', 'mask': [True], 'bid': '62500000000000000', 'commitment': '26135711486835189252810507112407250051211627558503078858520125577864847775053', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}]]
INFO:polyswarmclient:2018-12-06 16:56:48,440 Received block on chain side: {'number': 18281}
INFO:polyswarmclient:2018-12-06 16:56:48,503 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18301', 'uri': 'QmVoLQJ2nm4V6XiZXC9vEUrCaTHdkXS7y3crztZ5HwC9iK', 'guid': 'b41ef0f8-039f-4448-aadf-4d4135cdd94b', 'amount': '62500000000000000'}
INFO:polyswarmclient:2018-12-06 16:56:48,503 Received assertion on chain side: {'bounty_guid': '40862925-3e00-41b2-a946-365135d87070', 'mask': [True], 'bid': '62500000000000000', 'commitment': '26135711486835189252810507112407250051211627558503078858520125577864847775053', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}
WARNING:polyswarmclient.abstractmicroengine:2018-12-06 16:56:48,503 Received new bounty, but finished with testing mode
```

Running with `--testing 2` means our Microengine will respond to 2 bounties and then refuse to respond to further bounties by shutting itself off.
You can adjust this number if you want it to process more bounties in your tests.

But, your microengine will not have any bounties to process until there is an Ambassador sending bounties into the testnet.

#### Linux VM: Launch the Ambassador

In your Linux VM, now start the `ambassador`, which will submit bounties into the testnet, so your microengine can respond to them.
Start a new terminal.

```bash
cd orchestration
docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Shortly after this starts, you will see messages in your microengine terminal when it is processing bounties.

### All Done

Congrats!

Your Windows-Based Engine should now be responding to bounties placed on a local testnet hosted in your Linux VM.

Let your microengine run until it shuts itself off.

Take a close look at the output of your engine to ensure it's doing what you want it to :)
