## Linux Development Environment


### System Requirements

* x86-64 CPU
* 4GB of RAM


### Docker

We've Docker-ized as many things as we could to make it as easy as possible to get started and, later, to get testing.

You need to install Docker-CE (base) as well as Docker Compose (packaged with Docker in all modern releases).
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

Once installed, verify that the installation works.

```bash
docker -v
```

Should output at least: `Docker version 18.05.0-ce build f150324`

```bash
$ docker-compose -v
```

Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`


### Git

We'll need to grab a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.


### Python

PolySwarm development requires Python 3.5.4 or above.
Please [install Python](https://www.python.org/downloads/) for your development platform.


### (Optional) Set up a Virtual Environment (virtualenv)

If you plan to use this Windows installation for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

> Info: If you install `polyswarm-client` in a virtualenv, you'll need to "activate" the virtualenv (see above) each time you open a shell.


### Install `polyswarm-client` Libraries

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

[Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file ->](TODO: link to tut-eicar.md)




