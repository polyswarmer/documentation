## PolySwarm Hive

### What is Hive

PolySwarm Hive is an invite-only testnet to facilitate the development of microengines and arbiters.

### How to Apply

Hive is (currently) invite-only. Message us on [Twitter](https://twitter.com/PolySwarm), join our Discord or otherwise hunt us down for an invite :)

### What we Need from You

When you are invited, we will need two things from you:

1. an SSH public key
2. a username

### Connecting to Hive

Connecting to the Hive has been designed to be as simple as possible. We have two subdomains that you will need to use, and a one-liner connect.

* `gate.polyswarm.io` is our bastion host. All traffic is routed through there via SSH.
* `hive.polyswarm.io` is the endpoint where you can access `polyswarmd`.

For this next command you should run it in a separate tab, terminal, inside `tmux`, or any other means to leave this command running.

```bash
ssh -i /path/to/key -L 31337:hive.polyswarm.network:31337 <user>@gate.polyswarm.io
```

You will not see a prompt on that terminal, but don't worry, you have an open tunnel.

With the open tunnel, you can point your microengine to the `polyswarmd` API at `http://localhost:31337`.

### Verify connection

An easy way to make sure you have a valid connection to reach `polyswarmd`, try the commands below. If everything is working, you should see a json response like `{"status": "OK", "result":"some_value"}`.

```bash
curl http://localhost:31337/bounites
curl http://localhost:31337/balances/<address>/nct
```

### Using polyswarmd

Visit the [polyswarmd api docs](API-polyswarm) for the API specification.