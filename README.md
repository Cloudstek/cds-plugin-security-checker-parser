# CDS Plugin Security Checker Parser

This is a simple plugin for [cds](https://github.com/ovh/cds) based on the [npm-audit-parser plugin](https://github.com/ovh/cds/tree/master/contrib/grpcplugins/action/plugin-npm-audit-parser) but to parse reports from [sensiolabs/security-checker](https://github.com/sensiolabs/security-checker).

Currently used internally only and has no tests or whatever but works with CDS 0.47.

## Building

Check out the [Makefile](./Makefile) for cross-compiling the binaries.

## Installation

Use `cdsctl` to install the plugin.

```bash
cdsctl admin plugins import plugin-security-checker-parser.yml
cdsctl admin plugins binary-add plugin-security-checker-parser build/plugin-security-checker-parser-linux-amd64.yml build/plugin-security-checker-parser-linux-amd64
```
