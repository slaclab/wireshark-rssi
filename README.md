
# Wireshark RSSI

This repository contains the source code for a Wireshark packet dissector for the Reliable SLAC Streaming Protocol (RSSI).

## Prerequisites

* C99 Compiler
* make
* pkg-config
* wireshark >= 4.0 + development libraries

## Compiling & Installing

This will install the plugin to ~/.local by default.

```sh
make
make install WIRESHARK_VER=4.2 # Change to your version of wireshark
```

