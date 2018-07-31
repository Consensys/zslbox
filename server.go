package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"

	"github.com/consensys/zslbox/sha256"
	"github.com/consensys/zslbox/snark"
	"github.com/consensys/zslbox/zsl"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// ZSLServer implements ZSLBox server interface as defined in zslbox.proto
type ZSLServer struct {
}

// NewZSLServer returns a new ZSL Server
func NewZSLServer() *ZSLServer {
	return &ZSLServer{}
}

// GetCommitment returns SHA256(note.Rho || note.Pk || note.Value)
// where note.Value is in little endian byte order
func (server *ZSLServer) GetCommitment(ctx context.Context, note *zsl.Note) (*zsl.Bytes, error) {
	log.Debugw("GetCommitment",
		"note.Rho", hex.EncodeToString(note.Rho),
		"note.Pk", hex.EncodeToString(note.Pk),
		"note.Value", note.Value,
	)
	return &zsl.Bytes{Bytes: computeCommitment(note.Rho, note.Pk, note.Value)}, nil
}

// GetSendNullifier returns SHA256(0x00 || note.Rho)
func (server *ZSLServer) GetSendNullifier(ctx context.Context, note *zsl.Note) (*zsl.Bytes, error) {
	log.Debugw("GetSendNullifier", "rho", hex.EncodeToString(note.Rho))
	return &zsl.Bytes{Bytes: computeSendNullifier(note.Rho)}, nil
}

// GetSpendNullifier returns SHA256(0x01 || shieldedInput.Rho || shieldedInput.Sk)
func (server *ZSLServer) GetSpendNullifier(ctx context.Context, shieldedInput *zsl.ShieldedInput) (*zsl.Bytes, error) {
	log.Debugw("GetSpendNullifier",
		"shieldedInput.Rho", hex.EncodeToString(shieldedInput.Rho),
		"shieldedInput.Sk", hex.EncodeToString(shieldedInput.Sk),
	)
	return &zsl.Bytes{Bytes: computeSpendNullifier(shieldedInput.Rho, shieldedInput.Sk)}, nil
}

// GetNewAddress returns a tuple (Pk, Sk) where Pk is the paying (public) key and Sk is the secret key
func (server *ZSLServer) GetNewAddress(context.Context, *zsl.Void) (*zsl.ZAddress, error) {
	// create address
	toReturn := &zsl.ZAddress{
		Sk: make([]byte, zsl.HashSize),
	}

	// private key SK = 32 random bytes
	_, err := rand.Read(toReturn.Sk)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "couldn't read from rand")
	}

	// public key PK = Sha256(SK)
	pk := sha256.Sum256(toReturn.Sk)
	toReturn.Pk = pk[:]

	// return result
	log.Debugw("GetNewAddress returning", "pk", hex.EncodeToString(toReturn.Pk), "sk", hex.EncodeToString(toReturn.Sk))
	return toReturn, nil
}

// Sha256Compress applies SHA-256 to one input block, excluding the padding step specified in [NIST2015, Section 5.1]
func (server *ZSLServer) Sha256Compress(ctx context.Context, input *zsl.Bytes) (*zsl.Bytes, error) {
	log.Debug("Sha256Compress")
	h := sha256.NewCompress()
	h.Write(input.Bytes)
	return &zsl.Bytes{Bytes: h.Compress()}, nil
}

// CreateShielding computes a zkSNARK and a note commitment for given note.
// Also returns a sendNullifier to ensure note.Rho (random) is unique
func (server *ZSLServer) CreateShielding(ctx context.Context, note *zsl.Note) (*zsl.Shielding, error) {
	log.Debugw("CreateShielding",
		"note.Rho", hex.EncodeToString(note.Rho),
		"note.Pk", hex.EncodeToString(note.Pk),
		"note.Value", note.Value,
	)

	toReturn := &zsl.Shielding{}
	toReturn.Snark = snark.ProveShielding(note.Rho, note.Pk, note.Value)
	toReturn.SendNullifier = computeSendNullifier(note.Rho)
	toReturn.Commitment = computeCommitment(note.Rho, note.Pk, note.Value)

	return toReturn, nil
}

// CreateUnshielding computes a zkSNARK, nullifiers for given input, using Unshielding circuit
func (server *ZSLServer) CreateUnshielding(ctx context.Context, shieldedInput *zsl.ShieldedInput) (*zsl.Unshielding, error) {
	log.Debugw("CreateUnshielding",
		"input.Rho", hex.EncodeToString(shieldedInput.Rho),
		"input.Sk", hex.EncodeToString(shieldedInput.Sk),
		"input.TreeIndex", shieldedInput.TreeIndex,
		"input.Value", shieldedInput.Value,
	)

	// generate proof
	toReturn := &zsl.Unshielding{}
	toReturn.Snark = snark.ProveUnshielding(shieldedInput.Rho, shieldedInput.Sk, shieldedInput.Value, shieldedInput.TreeIndex, shieldedInput.TreePath)
	toReturn.SendNullifier = computeSendNullifier(shieldedInput.Rho)
	toReturn.SpendNullifier = computeSpendNullifier(shieldedInput.Rho, shieldedInput.Sk)

	return toReturn, nil
}

// CreateShieldedTransfer takes 2 notes as inputs (known Sk) and 2 desired output notes.
// It returns the zkSNARK, the spend nullifiers for the inputs, and the commitments & send nullifiers for outputs
func (server *ZSLServer) CreateShieldedTransfer(ctx context.Context, request *zsl.ShieldedTransferRequest) (*zsl.ShieldedTransfer, error) {
	log.Debug("CreateShieldedTransfer")
	// check input size
	if len(request.Inputs) != 2 || len(request.Outputs) != 2 {
		return nil, grpc.Errorf(codes.InvalidArgument, "expecting 2 inputs and 2 outputs")
	}

	toReturn := &zsl.ShieldedTransfer{}
	toReturn.Snark = snark.ProveTransfer(
		request.Inputs[0].Rho, request.Inputs[0].Sk, request.Inputs[0].Value, request.Inputs[0].TreeIndex, request.Inputs[0].TreePath,
		request.Inputs[1].Rho, request.Inputs[1].Sk, request.Inputs[1].Value, request.Inputs[1].TreeIndex, request.Inputs[1].TreePath,
		request.Outputs[0].Rho, request.Outputs[0].Pk, request.Outputs[0].Value,
		request.Outputs[1].Rho, request.Outputs[1].Pk, request.Outputs[1].Value,
	)

	toReturn.SendNullifiers = [][]byte{
		computeSendNullifier(request.Outputs[0].Rho),
		computeSendNullifier(request.Outputs[1].Rho),
	}

	toReturn.Commitments = [][]byte{
		computeCommitment(request.Outputs[0].Rho, request.Outputs[0].Pk, request.Outputs[0].Value),
		computeCommitment(request.Outputs[1].Rho, request.Outputs[1].Pk, request.Outputs[1].Value),
	}

	toReturn.SpendNullifiers = [][]byte{
		computeSpendNullifier(request.Inputs[0].Rho, request.Inputs[0].Sk),
		computeSpendNullifier(request.Inputs[1].Rho, request.Inputs[1].Sk),
	}

	return toReturn, nil
}

// VerifyShielding ensures that the provided Shielding proof is valid. It takes as input the zkSNARK,
// the send nullifier, commitment and value of the shielded note.
func (server *ZSLServer) VerifyShielding(ctx context.Context, request *zsl.VerifyShieldingRequest) (*zsl.Result, error) {
	log.Debugw("VerifyShielding",
		"snark", hex.EncodeToString(request.Shielding.Snark),
		"sendNullifier", hex.EncodeToString(request.Shielding.SendNullifier),
		"commitment", hex.EncodeToString(request.Shielding.Commitment),
		"value", request.Value,
	)
	if len(request.Shielding.Snark) != zsl.ProofSize {
		return nil, grpc.Errorf(codes.InvalidArgument, "proof size must be %d", zsl.ProofSize)
	}

	isValid := snark.VerifyShielding(request.Shielding.Snark, request.Shielding.SendNullifier, request.Shielding.Commitment, request.Value)

	return &zsl.Result{Result: isValid}, nil
}

// VerifyUnshielding ensures that the provided Unshielding proof is valid. It takes as input the zkSNARK,
// the spend nullifier, the tree root and value of the shielded note.
func (server *ZSLServer) VerifyUnshielding(ctx context.Context, request *zsl.VerifyUnshieldingRequest) (*zsl.Result, error) {
	log.Debugw("VerifyUnshielding",
		"snark", hex.EncodeToString(request.Snark),
		"spendNullifier", hex.EncodeToString(request.SpendNullifier),
		"treeRoot", hex.EncodeToString(request.TreeRoot),
		"value", request.Value,
	)
	if len(request.Snark) != zsl.ProofSize {
		return nil, grpc.Errorf(codes.InvalidArgument, "proof size must be %d", zsl.ProofSize)
	}

	isValid := snark.VerifyUnshielding(request.Snark, request.SpendNullifier, request.TreeRoot, request.Value)

	return &zsl.Result{Result: isValid}, nil
}

// VerifyShieldedTransfer ensures that the provided shielded transfer proof is valid.
// It takes as input the zkSNARK, treeRoot, spend nullifiers for inputs and send nullifiers & commitments
// for outputs
func (server *ZSLServer) VerifyShieldedTransfer(ctx context.Context, request *zsl.VerifyShieldedTransferRequest) (*zsl.Result, error) {
	// check input size
	if len(request.ShieldedTransfer.SendNullifiers) != 2 || len(request.ShieldedTransfer.SpendNullifiers) != 2 || len(request.ShieldedTransfer.Commitments) != 2 {
		return nil, grpc.Errorf(codes.InvalidArgument, "expecting 2 spend/sent nullifiers and commitments")
	}

	if len(request.ShieldedTransfer.Snark) != zsl.ProofSize {
		return nil, grpc.Errorf(codes.InvalidArgument, "proof size must be %d", zsl.ProofSize)
	}

	log.Debugw("VerifyShieldedTransfer",
		"snark", hex.EncodeToString(request.ShieldedTransfer.Snark),
		"treeRoot", hex.EncodeToString(request.TreeRoot),
		"spend_nf_1", hex.EncodeToString(request.ShieldedTransfer.SpendNullifiers[0]),
		"spend_nf_2", hex.EncodeToString(request.ShieldedTransfer.SpendNullifiers[1]),
		"send_nf_1", hex.EncodeToString(request.ShieldedTransfer.SendNullifiers[0]),
		"send_nf_2", hex.EncodeToString(request.ShieldedTransfer.SendNullifiers[1]),
		"commitment_1", hex.EncodeToString(request.ShieldedTransfer.Commitments[0]),
		"commitment_2", hex.EncodeToString(request.ShieldedTransfer.Commitments[1]),
	)

	isValid := snark.VerifyTransfer(request.ShieldedTransfer.Snark,
		request.TreeRoot,
		request.ShieldedTransfer.SpendNullifiers[0],
		request.ShieldedTransfer.SpendNullifiers[1],
		request.ShieldedTransfer.SendNullifiers[0],
		request.ShieldedTransfer.SendNullifiers[1],
		request.ShieldedTransfer.Commitments[0],
		request.ShieldedTransfer.Commitments[1])

	return &zsl.Result{Result: isValid}, nil
}

// -------------------------------------------------------------------------------------------------
// Private functions

// cm = SHA256(rho || pk || v) where v is in little endian byte order
func computeCommitment(rho []byte, pk []byte, v uint64) []byte {
	vbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(vbuf, v)

	h := sha256.New()
	h.Write(rho)
	h.Write(pk)
	h.Write(vbuf)
	return h.Sum(nil)
}

// send nullifier, SHA256(0x00 || rho)
func computeSendNullifier(rho []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(rho)
	return h.Sum(nil)
}

// spend nullifier SHA256(0x01 || rho || sk)
func computeSpendNullifier(rho []byte, sk []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(rho)
	h.Write(sk)
	return h.Sum(nil)
}
