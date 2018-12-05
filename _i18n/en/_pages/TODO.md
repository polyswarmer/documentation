# Assorted TODOs

* change the names of tutorial files


TODO: 
# Creating a Linux Engine

Linux Docker projects are based directly on `polyswarm-client`.

If your scanner does not have a disjoint "backend" (see above), configuration is likely as simple as:
1. Make modifications to `myengine.py` per tutorials found at `https://docs.polyswarm.io`.
2. Have these modifications call out to, e.g. your command line scanner binary.
3. Include your scanner binary / SDK in the `Dockerfile`.
4. If your scanner does have a disjoint "backend", then you'll also need to author a Docker Compose file (`docker-compose.yml`) that describes this backend service and exposes it to the frontend `polyswarm-client` modifications.

See references in `has_backend` section above for examples.

