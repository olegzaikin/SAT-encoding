SAT-encoding - SAT instance generator for MD4, SHA-1, SHA-256
=============================================================

### About

Sources and benchmarks for the paper

[Oleg Zaikin. Preimage attacks on round-reduced MD5, SHA-1, and SHA-256 using parameterized SAT solver // Constraints. Vol. 31. 2026](https://link.springer.com/article/10.1007/s10601-025-09383-0).

The sources are an extension of a [repository](https://github.com/saeednj/SAT-encoding) by Saeed Nejati:

In this extension, intermediate preimage attacks between rounds (or steps) i and i+1 can now be generated in the form of CNFs.

### Directories overview

/core - an encoder for the basic operations.
/crypto - Preimage/collision attack on MD4, SHA-1, and SHA-256.
/cnfs - CNFs encoding preimage attacks on round-reduced SHA-256 (from the Constraints paper).

### Compiling

The espresso logic minimizer must be installed beforehand.
E.g. it can be taken from https://github.com/classabbyamp/espresso-log

After the espresso is installed
> cd crypto
> make

### Running

To generate a template CNF (without known output) encoding the first 18 rounds (out of 64) of SHA-256, run:

./satencoding -f sha256 -t 1 -r 18 -a preimage --template_cnf > nossum_sha256_preimage_18r_template.cnf

To generate CNFs encoding standard (non-intermediate) preimage attacks
on MD4, SHA-1, or SHA-256, run:

> ./gen_cnfs.sh

To generate CNFs encoding intermediate preimage attacks on SHA-256, run:

> ./gen_weakM_cnfs.sh

### Citation
If you use these sources or/and data, please cite:

```
@article{Zaikin2026-Constraints,
  author       = {Oleg Zaikin},
  title        = {Preimage attacks on round-reduced {MD5}, {SHA-1}, and {SHA-256} using parameterized {SAT} solver},
  journal      = {Constraints},
  volume       = {31},
  year         = {2026}
}
```
