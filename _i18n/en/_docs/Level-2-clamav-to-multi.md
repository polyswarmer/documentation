## The More The Merrier: YARA

This tutorial will show you how to combine multiple analysis backends and outlines a basic verdict distillation primitive. 
The two backends will be `ClamAV` (from the last tutorial) and [`YARA`](https://virustotal.github.io/yara/). 

Before we start, make sure that you have the latest code from these repos:
* [**polyswarm/microengine**](https://github.com/polyswarm/microengine)
* [**polyswarm/orchestration**](https://github.com/polyswarm/orchestration)
And of course,`docker` and `docker-compose` are still requirements as well. 
These projects are dockerized for your convenience. 

## Adding YARA to our Microengine

Check out Docker-yar if you're curious about how to add YARA to a docker image. 
Credit to [blacktop](https://hub.docker.com/r/blacktop/yara/~/dockerfile/)

```sh
cd microengine
docker build -t polyswarm/microengine -f docker/Docker-yar .
```

Now you have a docker container with YARA installed. 
However, we need some rules for YARA. 
The [Yara-Rules](https://github.com/Yara-Rules/rules) repo is a convenient place to get some for free.

```sh
#(from root of microengine repo)
cd src/yara && git clone https://github.com/Yara-Rules/rules
#(rebuild so that your docker container has your new rules)
docker build -t polyswarm/microengine -f docker/Docker-yar .
```

## Code and Configuration

Let's get into it!

### Config
If you have your own YARA rules index file and want to use that instead, edit the following snippet in `microengine/src/microengine/clamyara.py` to point to your own rules/index file. 
The easiest way is to just copy your rules to the `src/yara/rules` directory that already exists. 
If you don't copy your rules there, you'll need to add that location to either the `Dockerfile` as a line like: `COPY /path/to/your/rules/dir/ /wherever/you/want/it/in/the/container/` , or in the `tutorial2.yml` `docker-compose` file as a mounted volume. 
```py
# Yara rules import
RULES_DIR = 'src/yara/rules/'
rules = yara.compile(RULES_DIR + "malware/MALW_Eicar")
```
Since our mock ambassador only posts 2 files, EICAR and not_EICAR, it is sufficient to only include the relevant EICAR rule.
### Code

Yara-Python's `rules` object has a `match(path)` function that compares all of your rules to the file at the specified `path` and returns a list of the rules that the scanned file matched. 
Here's how we scan a file using YARA
```py
import yara
...
async def scan...
...
	with  tempfile.NamedTemporaryFile(mode='r+b',suffix='.ipfs') as f:
			f.write(content)
			#annoying filewriting stuff that is not pretty
			f.seek(0)
			f.flush()
			os.fsync(f.fileno())
			fpath = os.path.abspath(f.name)
			#yara scan
			matches = rules.match( (fpath), timeout=60 )
```
Nice! 
However, this tutorial is about using _multiple_ analysis backends, which means we need to have some way to get the result of both backends(YARA and ClamAV) and distill that into our verdict. 
More code!
If you took a peep at `src/microengine/clamyara.py` then you might have noticed some variables:

```py
async def scan(self, guid, content):	
	#state variables, res=result, met=metadata
	yara_res = False
	clam_res = False
	yara_met = ''
	clam_met = ''
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
		clam_met = result[1]
```

Finally, now that we have some accurate data in our variables, we can distill them into a usable and submissible verdict.
```py
#result
# if either finds a match, trust it and send it along
if( (yara_res|clam_res) ):
	assertion = True
	return bit, assertion, (yara_met+' '+clam_met)
# if not, oh well, it ain't malware :) (right???) 
elif ( not (yara_res|clam_res) ):
	assertion = False
	return bit, assertion, ''
```