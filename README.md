# fty-certificate-generator

Agent in charge of creating and managing SSL certificates for IPM2 services.

The agent provides the following operations:
- generate a self-signed certificate
- manage a Certificate Signing Request (CSR)
	- create CSR
	- import an external certificate signed against a pending CSR
- export current certificate in PEM format

## How to build

To build `fty-certificate-generator` project run:

```bash
./autogen.sh
./configure
make
make check # to run self-test
```

## How to run

To run `fty-certificate-generator` project:

* from within the source tree, run:

```bash
./src/fty-certificate-generator
```
