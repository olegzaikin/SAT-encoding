SAT-encoding - SAT instance generator for MD4, SHA-1, SHA-256
=============================================================

### About

Sources and benchmarks for the papers

Oleg Zaikin. Preimage attacks on round-reduced MD5, SHA-1, and SHA-256 using parameterized SAT solver // Constraints. Vol. 31. 2026.

The sources are an extension of the repository by Saeed Nejati:

https://github.com/saeednj/SAT-encoding

In this extension, intermediate preimage attacks between rounds (or steps) i and i+1 can now be generated in the form of CNFs.

### Directories overview

/core - an encoder for the basic operations.
/graph - Graph problems
/crypto - Preimage/collision attack on MD4, SHA-1, and SHA-256.
/arith - Integer arithmetic problems

### Compiling

The espresso logic minimizer must be installed beforehand.
E.g. it can be taken from https://github.com/classabbyamp/espresso-log

To make a crypto generator:
> cd crypto
> make

### Running
