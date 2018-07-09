## Welcome

In the first few tutorials you learned what a Polyswarm Microengine is, how to create a scratch to EICAR-enabled Microengine, and how to build out a ClamAV-inspired Microengine.

If you didn't go through the scratch or clamav Microengine guides, please read [Level 0: Scratch to EICAR](/Level-0-scratch-to-eicar) and [Level 1: ClamAV Microengine](/Level-1-ClamAV-microengine).

In this section, you're going to learn how to create a more advanced Microengine like ClamAV with Yara and other possibilities. 

## Recap: What is a Polyswarm Microengine?

Microengines encapulate security knowledge. If you have unique insight into a particular malware family, you can encapsulate your knowledge into a PolySwarm microengine, hook it up to the PolySwarm network and (potentially) earn passive income for your insight!

Microengines are what you make of them: signature-based, heuristic, sandboxed execution, whatever - you run it yourself, you maintain your secret sauce, all for the greater good. Your microengine is your representative on the PolySwarm network.

For those anxious for the code, this guide will reference and build on:
* [**polyswarmd**](https://github.com/polyswarm/polyswarmd): abstracts Ethereum and IPFS idiosyncrasies
* [**polyswarm-contracts**](https://github.com/polyswarm/polyswarm-contracts): the contracts your microengine must support

**Microengines and Arbiters overlap substantially in their behavior and composition, differing only in the Ethereum events they respond to.**

**Microengines are security experts' autonomous representatives in the PolySwarm marketplace.**

They:
1. listen for Bounties and Offers on the Ethereum blockchain
2. pull artifacts from IPFS
3. scan the artifacts 
4. determine a Nectar (NCT) wager amount
5. render an assertion (their verdict + wager)

The open source `polyswarmd` project aims to abstract items 1,2 & 5, allowing microengine developers to focus on item 3 & 4 - scanning artifacts and placing assertions against them.

This article assumes the use of `polyswarmd` and will focus exclusively on items 3 & 4.
As with (almost) all microengine design decisions, you may choose to use `polyswarmd` or build your own alternative.

### Microengine Components
Conceptually, a microengine is composed of:
1. `N` **analysis backends**: the scanners that ingest artifacts and determine `malicious` or `benign`. 
1. `1` **verdict distillation engine**: ingests analysis engine output, distills to a single `verdict` + a `confidence interval`
1. `1` **wager engine**: ingests verdict distillation output and market / competitive information and produces a `wager` in units of Nectar (NCT)
1. **glue** that binds all the above together, tracks state, communicates with the blockchain and IPFS

The exemplar microengines decompose these duties into distinct components.

## ClamAV Components

![ClamAV Architecture](/public-src/images/virusscanner-deployment.png)

ClamAV runs as a Linux daemon and has it’s own command protocol. 

The daemon listens for incoming connections on Unix and/or TCP socket and scans files or directories on demand. 
It reads the configuration from /etc/clamd.conf

It's recommended to prefix clamd commands with the letter z (eg. zSCAN) to indicate that the command will be delimited by a NULL character and that 
clamd should continue reading command data until a NULL character is read. 
The null delimiter assures that the complete command and its entire argument will be processed as a single command

Clamd recognizes the following commands :
1. PING
    -- Checkthe server's state. It should reply with "PONG".
2. VERSION
    -- Print the program and database versions.
3. RELOAD
    -- Reload the virus database.
4. SHUTDOWN
    -- Perform a clean exit
5. SCAN file/director
    -- Scan a file or directory(recrusively) with archive support enabled (if not disabled in clamd.conf). A full path is required.
6. CONTSCAN file/directory
    -- Scan file or directory(recursively) with archive support enabled.  
7. MULTISCAN file/directory
    -- Scan file in a standard way or scan directory (recursively) using multiple threads (to make scanning faster on SMP machines).
8. INSTREAM
    -- It is mandatory to prefix this command with n or z.

## YARA Components

![YARA Architecture](/public-src/images/virusscanner-deployment.png)

 YARA Rules are like the swiss army knife for malware research. 
 
Using YARA rules with ClamAV is simple - just place your YARA rule files into the ClamAV virus database location. This is `/usr/local/share/clamav` by default.

Alternatively, you can place them in other locations and reference them with the `–database` command line option for clamscan or the clamd.conf `DatabaseDirectory` parameter if you are using clamd and clamdscan.

## Set up a Microengine Development Environment

### Docker

We've Docker-ized as many things as we could to make it as easy as possible to get started, regardless of your development environment. Assuming Docker is installed, these images should *just work* under Windows, macOS and Linux.

To get started, you'll need Docker (base) as well as Docker Compose (packaged with Docker in all modern releases).
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

Once installed, verify that the installation works.

```sh
$ docker -v
Docker version 18.05.0-ce build f150324

$ docker-compose -v
docker-compose version 1.21.1, build 5a3f1a3
```

### Git

We'll need to grab a a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.

### Grab the Code

```sh
$ git clone https://github.com/polyswarm/microengine-clamav
$ git clone https://github.com/polyswarm/orchestration
```

### Spin Up a Development Enviroment

```sh
$ pushd orchestration
$ docker-compose -f dev.yml -f tutorial.yml up
```

That's it! You should be good to go, working on your fancy new Microengine-clamav.

## How to write a Clamav + YARA rules like MicroEngine

Your microengine (probably) *needs* to have the following functionality
- `ws transaction signings` - all transactions are sent over a websocket where they can be individually signed.
- `getArtifact` - send a GET web request to polyswarmd to download an artifact via polyswarmd IPFS
- `scan` - tells your analysis backend to process the artifact and process the output of your analysis backend
- `sendVerdict` - relay your analysis backend's verdict to polyswarmd via POST webrequest
- `waitForEvent()` - listen for events from polyswarmd (daemon), process events. Minimum functionality - handle/process bounties  

### Creating the Microengine-clamav

Let's start with main.go  

Open up your favorite IDE, text editor, VI or emacs

```sh
$ vi main.go
```

### Creating the YARA Rules

Example of how YARA rules are configured : 

```
rule silent_banker : banker
{
  meta:
    description = "This is just an example"
    thread_level = 3
    in_the_wild = true

  strings:
    $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
    $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
    $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

  condition:
    $a or $b or $c
}
```

The above rule is telling YARA that any file containing one of the three strings must be reported as silent_banker

### Create your own YARA rule

```sh
$ vi yara_office.yara
```

The YARA rules should look something like ...
  
```
rule BLAH_FILE_FOOTER
{
  meta:
    type = "MS Office DOC footer"
  strings:
    $msoffice_doc_footer = "blah" nocase
  condition:
    $msoffice_doc_footer
}

rule LOREM_FILE_BODY
{
  meta:
    type = "MS Office DOC body"
  strings:
    $msoffice_doc_body = "mel zril nominati" nocase
  condition:
    $msoffice_doc_body
}
```

###  Convert ClamAV to YARA rules

```go
// This method is used to write the final yara rule files
// It automatically creates all 3: Win, Linux, OS X
func writeRules(pt *platformSigs, fileType definitionType, signatureType definitionExtensionType) error {

  // parse the template
  tpl, err := template.ParseFiles("yara.tpl")
  if err != nil {
    return err
  }

  // cerate a buffer to store the in memory template
  var buffer bytes.Buffer

  // process the data
  err = tpl.Execute(&buffer, pt)
  if err != nil {
    fmt.Printf("Creation of rules for platform %s failed with error %s\n:", pt.Platform.String(), err)
    return err
  }

  // write the template to disk

  fileName := fileType.String() + "_" + pt.Platform.String() + ".yara"

  switch signatureType {
  case kHDB_EXTENSION:
    fileName = "file_" + fileName
  }

  fullPath := filepath.Join(rulesFolder, fileName)

  err = ioutil.WriteFile(fullPath, buffer.Bytes(), 0644)

  return err

}
```

### Test Your Brand New ClamAV-YARA Microengine!

```sh
$ go run main.go
```
