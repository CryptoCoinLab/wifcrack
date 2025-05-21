# wifcrack

This repository provides a small C module derived from a Java class used in a Bitcoin related project. The `configuration.h` and `configuration.c` files implement a `Configuration` structure and helper functions for managing solver configuration data.
The repository now also includes a very small `worker` module translated from the Java version.  It demonstrates how a worker can be driven by the `Configuration` object and provides simple result management routines.


## Examples

The `examples` directory contains example configuration files used by the unit
tests. Only a simple sample file is included due to the offline environment.
You may place additional `.conf` files in this directory to further exercise the
parser.

## Running tests

Compile and run the tests with:


```sh
gcc -Wall configuration.c test_configuration.c -o test_config
./test_config
```

The worker module can be built in a similar way by compiling `worker.c` together
with the configuration sources if you want to experiment with it.
