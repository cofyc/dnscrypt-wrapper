#!/bin/bash
#
# Depend on https://github.com/Cofyc/my-coding-style.
#

# C sources

format_c $(find . -name "*.[ch]" | grep -E -v '^\.\/(argparse|dns-protocol.h|rfc1035)')
