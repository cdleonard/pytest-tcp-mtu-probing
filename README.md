# Python tests for linux rfc4821 TCP MTU Probing

See https://datatracker.ietf.org/doc/html/rfc4821

To run: `./run.sh` which does `sudo tox` with additional logging.

It's possible to run pytest directly if depedencies are available and the
current user is allowed to create network namespaces.
