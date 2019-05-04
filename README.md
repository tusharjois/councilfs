# councilfs

An Incentivized, Resilient File Distribution System, created for JHU Blockchains & Cryptocurrencies, Spring 2019.

This code is a research proof-of-concept implementation of the PoR, alderman, and client aspects of our construction. **It is not intended for commercial use**.

## Installation 

This package is implemented in Go, and has been tested on version 1.12 of the Go compiler.

Install the following Go package to your `$GOPATH`:

```sh
```

Then, prepare your `$GOPATH` for installation:

```sh
mkdir -p $GOPATH/github.com/tusharjois
```

Finally, checkout the package.

```sh
cd $GOPATH/github.com/tusharjois
git checkout https://github.com/tusharjois/councilfs
cd councilfs/
```

## Tests 

To run the tests, make sure the package is properly installed to `$GOPATH`. Then, run the following:

```sh
go test github.com/tusharjois/councilfs/por
go test github.com/tusharjois/councilfs/aldermen
```

To run the microbenchmark data generator, run the following:

```sh
cd $GOPATH/github.com/tusharjois/councilfs
go run main.go
```

