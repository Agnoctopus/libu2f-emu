Universal 2nd Factor (U2F) Emulation C Library
==============================================

Libu2f-emu, provides a C Library for the U2F device emulations.

# API

The API is described in `src/u2f-emu.h` and `src/u2f-emu-type.h`.

It gives the possibility to create virtual emulated U2F devices with transport specific considerations.
Four transports are available:
- USB
- NFC
- BLUETOOTH
- AGNOSTIC

Once create, it is possible to interact with the devices by sending
and receiving transport specific data through the API.

# Device configuration

Each virtual device, for its configuration requires:
- an EC x509 certificate
- its EC private key
- 48 bits of entropy
- a global counter

All the files are grouped inside a setup_dir that can be created through the `setup.sh` script.

```shell
$ ./setup.sh <setup_dir>
```

# Examples

For each transport, a code example is available and can be built:
```shell
$ make examples
```

### USB:

Software that emulates U2F through a virtual USB device using UHID system API on Linux and the `libu2f-emu`.

```shell
$ ./examples/usb/u2f-emu-usb <setup_dir>
```
> You can easily test the virtual device my registering it on websites or by playing with it on https://webauthn.io/.

# Building

The project support two build systems:
- Autotools
- CMake

Setup the build system:
```shell
# Autotools
$ ./autogen.sh
$ ./configure

# CMake
$ mkdir build && cd build
$ cmake ..
```

Build and install the library:
```shell
$ make
$ make install
```

# Doc

The doc is generated using `doxygen`:
```shell
$ make doc
```
The doc can be accessed here: `doc/html/index.html`.

# Tests

Somes testsuites come with the project, these can be generated and run: `gtest` is required:
```shell
$ make check
```

# Coverage

The coverage and its html report can be easily generated: `gcov`, `gcovr` and `gtest` are required.
```shell
# Autotools
$ ./configure --enable-coverage
$ make coverage

# CMake
$ cmake -DCMAKE_BUILD_TYPE=Coverage ..
$ make coverage
```
The coverage html report can be accessed here: `coverage/index.html`.

# Pkg-config

After the installation, the pkg-config informations are set:
```shell
$ PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkgconf u2f-emu --libs --cflags
```

# License

This project is licensed under GPL-2.0.

# Author

César `MattGorko` Belley <cesar.belley@lse.epita.fr>
