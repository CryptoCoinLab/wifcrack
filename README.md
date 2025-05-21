# wifcrack

This repository provides a small C module derived from a Java class used in a Bitcoin related project. The `configuration.h` and `configuration.c` files implement a `Configuration` structure and helper functions for managing solver configuration data.


## Running tests

The repository includes a basic test program `test_configuration.c` that exercises the module. Compile and run it with:

```sh
gcc -Wall configuration.c test_configuration.c -o test_config
./test_config
```

