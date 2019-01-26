## System Requirements

* x86-64 CPU
* 8GB of RAM

These instructions are developed against and tested to work on Xubuntu 18.04 amd64.

## Install Docker

We've Docker-ized as many things as possible to make it easy to dive right in.

You need to install Docker-CE (base) as well as Docker Compose. If you do not have a recent Docker setup, please [install Docker now](https://docs.docker.com/install/).

Once installed, verify that the installation works by running

```bash
$ docker ps
```

Should output:

    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    

Next, [install `docker-compose`](https://docs.docker.com/compose/install/).

Once it is installed, verify the installation works by running:

```bash
$ docker-compose -v
```

Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`

After installing Docker, we recommend adding your user to the `docker` group so that you can easily issue `docker` commands without `sudo`:

```bash
$ sudo usermod -aG docker ${USER}
```

You'll need to reboot in order for the change to take effect.

## Install Git

We'll need to grab a few source code repositories; it'll be easiest to use Git. Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.

## Install Python & PIP

PolySwarm development requires Python 3.5.4 or above. Please install [Python](https://www.python.org/downloads/) and [PIP](https://pip.pypa.io/en/stable/installing/) for your development platform.

## (Optional) Set up a Virtual Environment (virtualenv)

If you plan to use this machine for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
pip install virtualenv
cd ~
virtualenv polyswarmvenv -p <PATH TO PYTHON 3.5.4 OR ABOVE>
source polyswarmvenv/bin/activate
```

## Install `polyswarm-client` Libraries

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    If you're using a virtualenv (see above), ensure that you activate it before installing polyswarm-client.
  </p>
</div>

Compiling & installing `polyswarm-client` libraries is simple.

First, install Python 3 headers / build requirements.

On Ubuntu, this is achieved with:

    $ sudo apt install python3-dev
    

Next:

```bash
pip install polyswarm-client
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