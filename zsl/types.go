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

import "crypto/rand"

const (
	HashSize  = 32
	TreeDepth = 29
	ProofSize = 584
)

// Hash is a type alias on a 32 byte array for clarity
type Hash = [HashSize]byte

// NewHash returns a 32 byte array from a byte slice
func NewHash(from []byte) Hash {
	if len(from) != HashSize {
		panic("zsl.hash length invalid")
	}

	var toReturn [HashSize]byte
	copy(toReturn[:], from)
	return toReturn
}

// RandomBytes returns a []byte filled with random bytes
func RandomBytes(length uint) []byte {
	toReturn := make([]byte, length)
	if _, err := rand.Read(toReturn); err != nil {
		panic(err)
	}
	return toReturn
}
