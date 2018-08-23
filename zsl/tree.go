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
	"errors"

	"github.com/jpmorganchase/zsl-q/zsl-golang/zsl/sha256"
)

// Tree is an incremental Merkle Tree of fixed depth
// as described in ZCash protocol
// It is rudimentary and for testing purposes only (needs optimization)
type Tree struct {
	depth              uint
	maxElements        uint
	nbCommitments      uint
	commitmentsIndices map[Hash]uint
	commitments        map[uint]Hash
	EmptyRootsByHeight []Hash
}

// NewTree returns a new Merkle Tree of fixed depth depth
func NewTree(depth uint) *Tree {
	// tree has max elements 2^depth
	toReturn := &Tree{depth: depth, maxElements: pow(2, int(depth))}

	// initialize data structs
	toReturn.commitmentsIndices = make(map[Hash]uint)
	toReturn.commitments = make(map[uint]Hash)
	toReturn.EmptyRootsByHeight = make([]Hash, depth+1)

	// create empty roots
	var node Hash // initialized to 0x000000..., empty leaf value
	toReturn.EmptyRootsByHeight[0] = node

	// starting from the leaf to the root, each depth level emptyRoot value
	// equals a shaCompress of it's descendant
	for h := uint(1); h <= depth; h++ {
		node = shaCompress(node, node)
		toReturn.EmptyRootsByHeight[h] = node
	}

	return toReturn
}

// Root computes and return the tree root value
func (tree *Tree) Root() Hash {
	return tree.computeSubTree(0, tree.depth)
}

// GetWitnesses return treeIndex and authPath from leaf to root
func (tree *Tree) GetWitnesses(commitment Hash) (uint, [][]byte, error) {
	treeIndex, ok := tree.commitmentsIndices[commitment]
	if !ok {
		return 0, nil, errors.New("commitment not found")
	}
	treePath := make([][]byte, tree.depth)

	index := treeIndex // leaf index (at height 0)

	// start at leaf and go up the tree
	for height := uint(0); height < tree.depth; height++ {
		sub := tree.computeSubTree(index^1, height)
		treePath[height] = make([]byte, 32)
		copy(treePath[height], sub[:])
		index >>= 1
	}

	return treeIndex, treePath, nil
}

// AddCommitment adds a commitment to the tree, and return its index
func (tree *Tree) AddCommitment(commitment Hash) (uint, error) {
	if _, ok := tree.commitmentsIndices[commitment]; ok {
		return 0, errors.New("commitment already exists")
	}
	if tree.nbCommitments >= tree.maxElements {
		return 0, errors.New("tree is full")
	}
	tree.commitmentsIndices[commitment] = tree.nbCommitments
	tree.commitments[tree.nbCommitments] = commitment
	tree.nbCommitments++
	return tree.nbCommitments - 1, nil
}

// -------------------------------------------------------------------------------------------------
// Private functions

// recursively computes a subTree
func (tree *Tree) computeSubTree(index, height uint) Hash {
	if tree.nbCommitments <= (index << height) {
		// if the other half of the tree is empty
		return tree.EmptyRootsByHeight[height]
	}
	if height == 0 {
		// we reached a leaf, return the leaf value (commitment)
		return tree.commitments[index]
	}

	return shaCompress(tree.computeSubTree(index<<1, height-1),
		tree.computeSubTree((index<<1)+1, height-1))
}

func shaCompress(left, right Hash) Hash {
	var toReturn [32]byte
	h := sha256.NewCompress()
	h.Write(left[:])
	h.Write(right[:])
	res := h.Compress()
	copy(toReturn[:], res)
	return toReturn
}

func pow(a, b int) uint {
	p := 1
	for b > 0 {
		if b&1 != 0 {
			p *= a
		}
		b >>= 1
		a *= a
	}
	return uint(p)
}
