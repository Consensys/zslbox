**Warning: ZSLBox is not production ready and should not be deemed secure. For instance, there is no gRPC certificate verification.**

# ZSLBox

ZSLBox offers some grpc endpoints to generate and verify proofs "à la ZCash": shielding, unshielding and shielded transfers.
It is derived from [Quorum ZSL](https://github.com/jpmorganchase/zsl-q) published in Oct. 2017 by the the ZCash team & JPM, and uses [libsnark](https://github.com/scipr-lab/libsnark) as a backend.

ZSLBox is blockchain agnostic, and can easily be integrated in Ethereum clients through precompiled contracts.

See [running the tests](#running-the-tests) for example usage.

See [simple geth fork]() for example integration.

The [ZCash protocol specification](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf) is a must read.


## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

**Libraries:** the server needs to link with `libsnark` / `libzsl`. 

`go build` will work on any platform, but `libzsl` compile script is provided only for Linux (see Dockerfile). On MacOS and Windows, it doesn't link with `libzsl` and mocks the snark related APIs.

### Running

The easiest way to build and run ZSLBox is through [docker](https://docs.docker.com/install/).
```
docker pull pegasystech/zslbox:latest
docker volume create zslkeys
docker run -p9000:9000 -d --name zslbox --mount source=zslkeys,target=/keys pegasystech/zslbox:latest 
```

**Note:** the proving and verifying keys will be generated (aka *trusted setup*) only if not present in `/keys`. It takes about a minute on a standard laptop. 

### Building


Clone the repo

```
go get -u github.com/consensys/zslbox
```

Compile libsnark, libzsl and zslbox

```
docker build . -t zslbox
```

Create a volume that will hold the proving and verifying keys

```
docker volume create zslkeys
```

Start ZSLBox

```
docker run -p9000:9000 --rm --name zslbox --mount source=zslkeys,target=/keys zslbox:latest 
```


### API Overview

Checkout [zslbox.proto](https://github.com/ConsenSys/zslbox/blob/master/zsl/zslbox.proto) for a quick overview of the APIs ZSLBox offers.

## Running the tests

The files `client.go` and `client_test.go` in the `zsl` package demonstrate how to connect to the gRPC server (ZSLBox), generate and verify proofs. 
```
cd zsl
ZSLBOX_URL=localhost:9000 go test
```
*note: you can ommit ZSLBOX_URL env variable if you're running ZSLBox on localhost:9000 - default value*

### Create and verify shielding

A shielding operation will take a `Note` as input. it returns the `proof` (zkSNARK) and the `commitment` derived from the `Note`. 
It also returns a `send nullifier` (different from the `spend nullifier`) that ensures the random parameter in the note `Rho` is unique. 

Typically, a blockchain would enforce the validity of the shielding operation; it would ensure your balance on the ledger (in clear) is bigger than the value of the note you created and shielded. 


```
// connect to ZSLBox
client, err := NewClient(zslboxURL)
defer client.Close()

// generate a new ZAddress (Pk, Sk)
address, err := client.ZSLBox.GetNewAddress(context.Background(), &Void{})

// create a Note
note := &Note{
	Pk:    address.Pk,
	Rho:   RandomBytes(HashSize),
	Value: rand.Uint64(),
}

// shielding operation
shielding, err := client.ZSLBox.CreateShielding(context.Background(), note)
// shielding.Snark, shielding.Commitment, shielding.SendNullifier

// verify the proof generated above
verifyResult, err := client.ZSLBox.VerifyShielding(context.Background(), &VerifyShieldingRequest{Shielding: shielding, Value: note.Value})
```

### Create and verify unshielding

The unshielding and shielded transfer operations (and circuits) are more complex than the shielding one. Among other things, you'll want to prove than you know a tuple (Note, `Note Commitment`) such that `Note Commitment` is in a Merkle tree at a specific index. 
For testing purposes, the `zsl` package provides a `Tree` that stores commitments and provides witnesses for our operations (`treeRoot`and `treePath`, aka Merkle Tree authentication path).

```
// commitment tree
tree := NewTree(TreeDepth)
cm, err := client.ZSLBox.GetCommitment(context.Background(), note)
tree.AddCommitment(cm)

// get witnesses for our circuit
treeIndex, treePath, err := tree.GetWitnesses(cm)

// a known Note
shieldedInput := &ShieldedInput{
	Sk:        address.Sk,
	Rho:       note.Rho,
	Value:     note.Value,
	TreeIndex: uint64(treeIndex),
	TreePath:  treePath,
}

// unshielding
unshielding, err := client.ZSLBox.CreateUnshielding(context.Background(), shieldedInput)

// verify unshielding
treeRoot := tree.Root()
verifyRequest := &VerifyUnshieldingRequest{
	Snark:          unshielding.Snark,
	SpendNullifier: unshielding.SpendNullifier,
	Value:          note.Value,
	TreeRoot:       treeRoot[:],
}
verifyResult, err := client.ZSLBox.VerifyUnshielding(context.Background(), verifyRequest)
```

## Developers


### gRPC

You'll need to install `protobuf`, `grpc` and `protoc-gen-go` (or other plugin if you want to generate a client for another language; ex `protoc-gen-grpc-java`). Instructions [here](https://grpc.io/docs/quickstart/go.html).

Regenerate `zslbox.pb.go` from `zslbox.proto`, at the root of the repo:
```
go generate
```
### Formatting

We use `go fmt`. If you don't have a plugin to run it automatically in your Go environment, consider using our pre-commit hook
```
ln -s $(pwd)/pre-commit .git/hooks/
```

### Dependencies (/vendor)

ZSLBox uses [dep](https://golang.github.io/dep/) for dependency management.

### Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our [code of conduct](CODE_OF_CONDUCT.md), and the process for submitting pull requests to us.

### Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/consensys/zslbox/tags). 


## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* **The ZCash team** - *Amazing work on Zero Security Layer and ZCash protocol specification* - Original Copyright 2017 Zerocoin Electric Coin Company LLC

