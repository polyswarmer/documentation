## The More The Merrier: YARA

This tutorial will show you how to combine multiple analysis backends and outlines a basic verdict distillation primitive. The two backends will be `ClamAV` (from the last tutorial) and [YARA](https://virustotal.github.io/yara/). 

Before we start, make sure that you have the latest code from these repos:
* [**polyswarm/microengine**](https://github.com/polyswarm/microengine)
* [**polyswarm/orchestration**](https://github.com/polyswarm/orchestration)

And of course,`docker` and `docker-compose` are still requirements as well. These projects are dockerized for your convenience. 

## Adding YARA to our Microengine

Check out Docker-yar if you're curious how to add YARA to a docker image. Credit to [blacktop](https://hub.docker.com/r/blacktop/yara/~/dockerfile/)

```sh
cd microengine
docker build -t polyswarm/microengine -f docker/Docker-yar .
```

Now you have a docker container with YARA installed. However, we need some rules for YARA. I included the [Yara-Rules](https://github.com/Yara-Rules/rules) repo as a submodule, so you can run the following to get some for free!

```sh
git pull --recurse-submodules
```
### Config
Let's get into the microengine code and configuration.

If you have your own YARA rules index file and want to use that instead, edit the following in `microengine/src/microengine/clamyara.py` to point to your own rules. The easiest way is to just copy your rules to the `src/yara/rules directory` that already exists.If you don't copy your rules in, you'll need to add that location to either the `Dockerfile` as a line like: `COPY /path/to/your/rules/dir/ /wherever/you/want/it/in/the/container/` , or in the `tutorial2.yml` `docker-compose` file as a mounted volume. 
```py
# Yara rules import
RULES_DIR = 'src/yara/rules/'
rules = yara.compile(RULES_DIR + "malware_index.yar")
```


