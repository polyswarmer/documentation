## System Requirements

* x86-64 CPU
* 8GB of RAM

These instructions are developed against and tested to work on Ubuntu 18.04 amd64.


## Install Docker

We've Docker-ized as many things as possible to make it easy to dive right in.

You need to install Docker-CE (base) as well as Docker Compose.
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


## Install Git

We'll need to grab a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.


### Install Python & PIP

PolySwarm development requires Python 3.5.4 or above.
Please install [Python](https://www.python.org/downloads/) and [PIP](https://pip.pypa.io/en/stable/installing/) for your development platform.


## (Optional) Set up a Virtual Environment (virtualenv)

If you plan to use this machine for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
pip install virtualenv
cd ~
virtualenv polyswarmvenv -p <PATH TO PYTHON 3.5.4 OR ABOVE>
source polyswarmvenv/bin/activate
```


## Install `polyswarm-client` Libraries

> Info: If you're using a virtualenv (see above), ensure that you activate it before installing `polyswarm-client`.

Installing `polyswarm-client` is as simple as:
```bash
pip install git+https://github.com/polyswarm/polyswarm-client.git#egg=polyswarm-client
```

## Verify Installation

You should now have a working development environment!

To verify, simply try importing `polyswarmclient`:
```bash
$ python
...
>>> import polyswarmclient
>>>
```

You should be able to import `polyswarmclient` without issue.

Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file.

[Make a "Hello World" Microengine →](/microengines-scratch-to-eicar/)
