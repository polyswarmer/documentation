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


### Orchestration

The `orchestration` project will help us with testing our engine later.

Clone it:
```bash
git clone https://github.com/polyswarm/orchestration
```

### Continue Configuring Your Environment

That's a wrap for all the Linux-specific items!

[Let's regroup with Windows-based engine developers to finalize our environment ->](TODO: dev_env_common.md). 





