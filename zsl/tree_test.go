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
	"bytes"
	"testing"
)

func TestEmptyRoot(t *testing.T) {
	tree := NewTree(TreeDepth)

	// compute root
	root := tree.Root()

	// compares it with empty root at height TreeDepth
	if !bytes.Equal(root[:], tree.EmptyRootsByHeight[TreeDepth][:]) {
		t.Fatal("expected root of empty tree to be equal to empty root")
	}

}

func TestWitnesses(t *testing.T) {
	tree := NewTree(2) // maxElements = 2^2 = 4

	// generate a random commitment
	cm := NewHash(RandomBytes(HashSize))

	treeIndex, err := tree.AddCommitment(cm)
	if err != nil {
		t.Fatal(err)
	}

	// compute the auth path
	idx, treePath, err := tree.GetWitnesses(cm)
	if err != nil {
		t.Fatal(err)
	}
	if idx != treeIndex {
		t.Fatal("expected commitment indexes to match")
	}

	// tree Auth should have length 2 and contains emptyRootByHeight 0 and 1
	if len(treePath) != 2 {
		t.Fatal("expected length of auth path to be same as depth")
	}

	r1 := tree.EmptyRootsByHeight[0]
	r2 := tree.EmptyRootsByHeight[1]

	if !bytes.Equal(treePath[0], r1[:]) {
		t.Fatal("treePath[0] should be equal to leaf(1)")
	}

	if !bytes.Equal(treePath[1], r2[:]) {
		t.Fatal("treePath[1] should be equal to emptyRoot at height 1")
	}
}

func TestAddCommitment(t *testing.T) {
	tree := NewTree(2) // maxElements = 2^2 = 4

	// compute initial root
	initialRoot := tree.Root()

	// generate a random commitment
	cm := NewHash(RandomBytes(HashSize))

	// adds it to the tree
	cmIndex, err := tree.AddCommitment(cm)
	if err != nil {
		t.Fatal("couldn't add commitment to the tree", err)
	}
	if cmIndex != 0 {
		t.Fatal("first commitment should have index 0")
	}

	newRoot := tree.Root()
	if bytes.Equal(initialRoot[:], newRoot[:]) {
		t.Fatal("root should change after adding a commitment")
	}

	if _, err = tree.AddCommitment(cm); err == nil {
		t.Fatal("shouldn't add the same commitment twice without error")
	}

	// new commitment
	var i uint
	for i = 1; i < 4; i++ {
		cmIndex, err = tree.AddCommitment(NewHash(RandomBytes(HashSize)))
		if err != nil {
			t.Fatalf("couldn't add commitment %d to the tree: %s", i, err.Error())
		}
		if cmIndex != i {
			t.Fatalf("commitment should have index %d", cmIndex)
		}

	}

	// try to add more than capacity of tree
	if _, err = tree.AddCommitment(NewHash(RandomBytes(HashSize))); err == nil {
		t.Fatal("shouldn't add a commitment to a full tree")
	}
}
