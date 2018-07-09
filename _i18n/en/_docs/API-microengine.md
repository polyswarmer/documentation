## Micro Engine

A Microengine is a program that **scans** artifacts. It is an interface that operates between Polyswarmd and the Analysis Backend.

## Analysis Backend

Microengines enwrap an Analysis Backend, an algorithm that detects malware signatures and yields the infection results.

## How to make Micro Engine.

XXX maybe this part is going to be merged into **Creating-a-PolySwarm-Micro-Engine-for-Fun-and-Profit.md**

### Required

```
Docker version         >= 18.x
Docker Compose version >= 1.21.x  
```

### 1. Launch Polyswarmd

XXX

### 2. Microengine 

```
- [public]  main(host, port, data_dir, password)
- [private] jsonify(json_string)
- [private] scan(host, port, data_dir, password)
- [private] assert(data_hash, ...) 
- [private] get_artifacts()
```

###### *main(host, port, data_dir, password)*

main starts the microengine process. host, port means the host/port on which `polyswarmd` is running.
For instance, if your polyswarmd is running on localhost:31337, then the microengine should be called such as:

```
MicroEngine.main(localhost, 31337, "$HOME/.ethereum/priv_testnet", "password")
```

The data_dir is your .ethereum data directory on which your ethereum account hosted in `keystore`.
`password` is the key to that account.

###### *jsonify(json_string)*

jsonify parses the json_string sent from `polyswarmd` into Hash object with tangible keys and values.
the json_string is sent from `polyswarmd` when bounty posted onto it.


###### *scan(host, port, data_dir, password)*

This does the following:

- establish the **websocket connection** between `polyswarmd` (ws://[host:port]/events/home) for getting event
- establish the **websocket connection** between `polyswarmd` (ws://[host:port]/transactions) for getting transactions
- when `bounty` comes, 
```
a-1. sign the transaction
a-2. send the transaction
a-3. [assrtion process] retrieve artifacts from IPFS
a-4. [assrtion process] scan artifacts (3.)
a-5. [assrtion process] post the assrtion result to `polyswarmd`
```

###### *assert(data_hash, ...)*

This method is part of the former (scan) method, which does:

```
a-3. [assrtion process] retrieve artifacts from IPFS
a-4. [assrtion process] scan artifacts (3.)
a-5. [assrtion process] post the assrtion result to `polyswarmd`
```

1. Check if the event (json) sent from `polyswarmd` is of type `bounty`, it means bounty has been posted to polyswarmd.
2. if (1.) is True, (a-3) retrieve artifacts from IPFS.
3. [Optional] Since you only can get the raw_text_format of the artifact from polyswarmd, you need to locally save the artifact as temporal file.
4. then you send the [raw_data/temporal file] of artifacts to your `analysis backend` and scan these.
5. (4.) should return the scanned result of each artifact, so post the result to the `polyswarmd` as **assertion**.
6. (5.)'s assertion should abide by the specific data format.

###### *get_artifacts(host, port, uri)*

## Links

- [scratch.go](https://gitlab.polyswarm.io/polyswarm/microengine-scratch/blob/master/scratch.go)

```
- readKeyFile(keyfile, auth)
- listenForTx(conn, key)
- connectToPolyswarm(host)
- retrieveFileFromIPFS(host, resource, id)
- scanBounty(host, uri)
- makeBoolMask(len)
- main()
```
