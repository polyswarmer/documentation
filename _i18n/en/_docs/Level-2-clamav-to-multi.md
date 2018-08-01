## The More The Merrier: YARA

This tutorial will show you how to combine multiple analysis backends and outlines a basic verdict distillation primitive. 
The two backends will be `ClamAV` (from the last tutorial) and [`YARA`](https://virustotal.github.io/yara/). 

Before we start, make sure that you have the latest code from these repos:


* [**polyswarm/microengine**](https://github.com/polyswarm/microengine)
* [**polyswarm/orchestration**](https://github.com/polyswarm/orchestration)


And of course,`docker` and `docker-compose` are still requirements as well. 
These projects are dockerized for your convenience. 

## Adding YARA to our Microengine

Refer to [this](https://hub.docker.com/r/blacktop/yara/~/dockerfile/) Dockerfile for instructions on including YARA in your own Docker image.

We need some rules for YARA.
The [Yara-Rules](https://github.com/Yara-Rules/rules) repo is a place to get some for free.
It is added as a submodule for your convenience.
```sh
#(from root of microengine repo)
git submodule update --init --recursive
#(rebuild so that your docker container has your new rules)
docker build -t polyswarm/microengine -f docker/Dockerfile .
```

## Code and Configuration

Let's get into it!

### Config
If you have your own YARA rules index file and want to use that instead, edit the following snippet in **`microengine/src/microengine/multi.py`** to point to your own rules/index file.
The easiest way is to just copy your rules to the `src/yara/rules` directory that already exists. 
If you don't copy your rules there, you'll need to add that location to either the `Dockerfile` as a line like: `COPY /path/to/your/rules/dir/ /wherever/you/want/it/in/the/container/` , or in the `tutorial2.yml` `docker-compose` file as a mounted volume. 
```py
# Yara rules import
RULES_DIR = 'data/yara-rules/'
rules = yara.compile(RULES_DIR + "malware/MALW_Eicar")
```
Since our mock ambassador only posts 2 files, EICAR and not_EICAR, it is sufficient for the content of this tutorial to only include the relevant EICAR rule.


### Code

Yara-Python's `rules` object has a `match(path)` function that compares all of your rules to the file at the specified `path` and returns a list of the rules that the scanned file matched. 
Here's how we scan a file using YARA:
```py
import yara
...
async def scan(self, guid, content):
...
	matches = rules.match(data=content)
    if matches:
       yara_res = True
```
Nice! 
However, this tutorial is about using _multiple_ analysis backends, which means we need to have some way to get the result of both backends(YARA and ClamAV) and distill that into our verdict. 
More code!
If you took a peep at `src/microengine/multi.py` then you might have noticed some variables:

```py
async def scan(self, guid, content):	
	#state variables, res=result, met=metadata
	yara_res = False
	clam_res = False
	yara_metadata = ''
	clam_metadata = ''
```

We'll use these to keep track of our state. 
In the case of the YARA backend, it is sufficient to write:
```py
	if matches:
		yara_res = True
```
For the ClamAV backend, there is a similarly small addition.
```py
	#clam scan
	result = self.clamd.instream(BytesIO(content)).get('stream')
	if len(result) >= 2 and result[0] == 'FOUND':
		clam_res = True
		clam_metadata = result[1]
```
Finally, now that we have some accurate data in our variables, we can distill them into a usable and submissible verdict.
```py
	# We assert on all artifacts
	bit = True

	# If either finds a match, trust it and send it along
	# If not, assert it is benign
	verdict = yara_res or clam_res
	metadata = ' '.join([yara_metadata, clam_metadata]).strip()

	return bit, verdict, metadata
```
Resulting in a completed `scan` method!

<details markdown="1">

<summary>Scan Method</summary>

### A completed Scan() method!

```python
async def scan(self, guid, content):
        """Scan an artifact with ClamAV + YARA
        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata
            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """
        yara_res = False
        clam_res = False
        yara_metadata = ''
        clam_metadata = ''
        # Yara rule matching
        matches = self.rules.match(data=content)
        if matches:
            yara_res = True
        # ClamAV scan
        result = self.clamd.instream(BytesIO(content)).get('stream')
        if len(result) >= 2 and result[0] == 'FOUND':
            clam_res = True
            clam_metadata = result[1]
        # We assert on all artifacts
        bit = True
        # If either finds a match, trust it and send it along
        # If not, assert it is benign
        verdict = yara_res or clam_res
        metadata = ' '.join([yara_metadata, clam_metadata]).strip()
        return bit, verdict, metadata
```

</details>

## Testing
Let's fire it up and test!
```sh
cd orchestration/
docker-compose -f dev.yml -f tutorial2.yml up
```
## Other Testing

We have also included a unit testing suite, for your convenience, so that you may quickly test the functionality of any microengine's scan function.

### Unit Testing

Start off by composing the clamAV daemon.
```sh
$ docker-compose -f dev.yml -f tutorial2.yml up clamav
```
In another pane, run a microengine container that's networked to the same network as clamd above:
```sh
$ docker run -it --net=orchestration_default polyswarm/microengine bash
bash-4.4# export CLAMD_HOST=clamav
bash-4.4# bash
bash-4.4# microengine-unit-test --backend multi --malware_repo dummy
Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
.
----------------------------------------------------------------------
Ran 1 test in 8.411s

OK
```
### Tricks
If you want more responsive and cleaner output, open up `tutorial2.yml` and add the `PYTHONUNBUFFERED` environment variable like so:
```yml
 tutorial:
        image: "polyswarm/microengine"
        depends_on:
            - polyswarmd
        environment:
           - PYTHONUNBUFFERED=1
```
then:
```sh
cd orchestration/
docker-compose -f dev.yml -f tutorial2.yml up | grep "tutorial"
#(tutorial is the name of the container with our microengine)
```
