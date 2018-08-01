// Copyright 2018 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zsl

import (
	"math/rand"
	"os"
	"testing"

	"golang.org/x/net/context"
)

var zslboxURL = "localhost:9000"

func init() {
	if userURL := os.Getenv("ZSLBOX_URL"); userURL != "" {
		zslboxURL = userURL
	}
}

func TestShieldedTransfer(t *testing.T) {
	// connect to zsl box
	t.Log("connecting to ", zslboxURL)
	client, err := NewClient(zslboxURL)
	defer client.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Commitment tree
	tree := NewTree(TreeDepth)

	// A shielded transfer takes 2 inputs and 2 outputs as parameters
	inputs := make([]*ShieldedInput, 2)
	outputs := make([]*Note, 2)

	// Generate ZAddresses
	addresses := make([]*ZAddress, 4)
	for i := 0; i < 4; i++ {
		address, err := client.ZSLBox.GetNewAddress(context.Background(), &Void{})
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = address
	}

	// Input notes
	input1 := &Note{Pk: addresses[0].Pk, Rho: RandomBytes(HashSize), Value: 42}
	input2 := &Note{Pk: addresses[1].Pk, Rho: RandomBytes(HashSize), Value: 0} // empty note

	// Output notes
	outputs[0] = &Note{Pk: addresses[2].Pk, Rho: RandomBytes(HashSize), Value: 40}
	outputs[1] = &Note{Pk: addresses[3].Pk, Rho: RandomBytes(HashSize), Value: 2}

	// Generate commitment for input note 1
	cmBytes, err := client.ZSLBox.GetCommitment(context.Background(), input1)
	if err != nil {
		t.Fatal(err)
	}
	cm := NewHash(cmBytes.Bytes)

	// Add input note commitments to the tree
	if _, err = tree.AddCommitment(cm); err != nil {
		t.Fatal(err)
	}

	// Get witnesses for our proof computation
	treeIndex1, treePath1, err := tree.GetWitnesses(cm)
	if err != nil {
		t.Fatal(err)
	}

	// Generate empty path for our "empty note"
	emptyPath := make([][]byte, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		emptyPath[i] = make([]byte, 32)
		copy(emptyPath[i], tree.emptyRootsByHeight[i][:])
	}

	// CreateShieldedTransfer inputs
	inputs[0] = &ShieldedInput{
		Sk:        addresses[0].Sk,
		Rho:       input1.Rho,
		Value:     input1.Value,
		TreeIndex: uint64(treeIndex1),
		TreePath:  treePath1,
	}

	inputs[1] = &ShieldedInput{
		Sk:        addresses[1].Sk,
		Rho:       input2.Rho,
		Value:     input2.Value,
		TreeIndex: 0,
		TreePath:  emptyPath,
	}

	shieldedTransferRequest := &ShieldedTransferRequest{
		Inputs:  inputs,
		Outputs: outputs,
	}

	// Create the proof
	t.Log("create shielded transfer proof")
	shielded, err := client.ZSLBox.CreateShieldedTransfer(context.Background(), shieldedTransferRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(shielded.Snark) != ProofSize {
		t.Fatalf("proof should be %dbytes", ProofSize)
	}

	// Now let's verify our proof.
	treeRoot := tree.Root()
	verifyResult, err := client.ZSLBox.VerifyShieldedTransfer(context.Background(),
		&VerifyShieldedTransferRequest{ShieldedTransfer: shielded, TreeRoot: treeRoot[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResult.Result {
		t.Fatal("expected proof that was just generated to be verified to true.")
	}
}

func TestShielding(t *testing.T) {
	// connect to zsl box
	t.Log("connecting to ", zslboxURL)
	client, err := NewClient(zslboxURL)
	defer client.Close()
	if err != nil {
		t.Fatal(err)
	}

	// get a new address
	t.Log("getting a new address")
	address, err := client.ZSLBox.GetNewAddress(context.Background(), &Void{})
	if err != nil {
		t.Fatal(err)
	}

	// create a note
	note := &Note{
		Pk:    address.Pk,
		Rho:   RandomBytes(HashSize),
		Value: rand.Uint64(),
	}

	// shield it.
	t.Log("shielding created note")
	shielding, err := client.ZSLBox.CreateShielding(context.Background(), note)
	if err != nil {
		t.Fatal(err)
	}

	if len(shielding.Snark) != ProofSize {
		t.Fatalf("proof should be %dbytes", ProofSize)
	}

	// now let's verify our proof.
	verifyResult, err := client.ZSLBox.VerifyShielding(context.Background(),
		&VerifyShieldingRequest{Shielding: shielding, Value: note.Value})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResult.Result {
		t.Fatal("expected proof that was just generated to be verified to true.")
	}
}

func TestUnshielding(t *testing.T) {
	// connect to zsl box
	t.Log("connecting to ", zslboxURL)
	client, err := NewClient(zslboxURL)
	defer client.Close()
	if err != nil {
		t.Fatal(err)
	}

	// commitment tree
	tree := NewTree(TreeDepth)

	// get a new address
	t.Log("getting a new address")
	address, err := client.ZSLBox.GetNewAddress(context.Background(), &Void{})
	if err != nil {
		t.Fatal(err)
	}

	// generate random note data
	note := &Note{
		Pk:    address.Pk,
		Rho:   RandomBytes(HashSize),
		Value: rand.Uint64(),
	}

	// computing commitment
	t.Log("computing note commitment")
	cmBytes, err := client.ZSLBox.GetCommitment(context.Background(), note)
	if err != nil {
		t.Fatal(err)
	}
	cm := NewHash(cmBytes.Bytes)

	// add commitment to the tree
	if _, err = tree.AddCommitment(cm); err != nil {
		t.Fatal(err)
	}

	// get witnesses for our circuit
	treeIndex, treePath, err := tree.GetWitnesses(cm)
	if err != nil {
		t.Fatal(err)
	}

	shieldedInput := &ShieldedInput{
		Sk:        address.Sk,
		Rho:       note.Rho,
		Value:     note.Value,
		TreeIndex: uint64(treeIndex),
		TreePath:  treePath,
	}

	// create unshielding with random data
	t.Log("creating unshielding proof with random input")
	unshielding, err := client.ZSLBox.CreateUnshielding(context.Background(), shieldedInput)
	if err != nil {
		t.Fatal(err)
	}

	// verify unshielding
	treeRoot := tree.Root()
	verifyRequest := &VerifyUnshieldingRequest{
		Snark:          unshielding.Snark,
		SpendNullifier: unshielding.SpendNullifier,
		Value:          note.Value,
		TreeRoot:       treeRoot[:],
	}
	verifyResult, err := client.ZSLBox.VerifyUnshielding(context.Background(), verifyRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResult.Result {
		t.Fatal("expected proof that was just generated to be verified to true.")
	}
}

func TestRandomVerifyShielding(t *testing.T) {
	// connect to zsl box
	t.Log("connecting to ", zslboxURL)
	client, err := NewClient(zslboxURL)
	defer client.Close()
	if err != nil {
		t.Fatal(err)
	}

	// // now let's verify our proof.
	for i := 0; i < 100; i++ {
		shielding := &Shielding{Snark: RandomBytes(ProofSize), Commitment: RandomBytes(HashSize), SendNullifier: RandomBytes(HashSize)}
		verifyResult, err := client.ZSLBox.VerifyShielding(context.Background(), &VerifyShieldingRequest{Shielding: shielding, Value: rand.Uint64()})
		if err != nil {
			t.Fatal(err)
		}
		if verifyResult.Result {
			t.Fatal("expected verify(random proof) to always be false")
		}
	}

}
