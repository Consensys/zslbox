// Original Copyright 2017 Zerocoin Electric Coin Company LLC
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

package snark

import (
	"fmt"
	"sync"
)

// Init() is only ever called once
var onceInit sync.Once

func Init(treeDepth uint, keyDir string) {
	onceInit.Do(func() {
		fmt.Println("snark init called")
	})
}

func ProveTransfer(input_rho_1 []byte,
	input_sk_1 []byte,
	input_value_1 uint64,
	input_tree_position_1 uint64,
	input_authentication_path_1 [][]byte,
	input_rho_2 []byte,
	input_sk_2 []byte,
	input_value_2 uint64,
	input_tree_position_2 uint64,
	input_authentication_path_2 [][]byte,
	output_rho_1 []byte,
	output_pk_1 []byte,
	output_value_1 uint64,
	output_rho_2 []byte,
	output_pk_2 []byte,
	output_value_2 uint64) []byte {
	toReturn := make([]byte, 584)

	return toReturn
}

func VerifyTransfer(proof []byte,
	anchor []byte,
	spend_nf_1 []byte,
	spend_nf_2 []byte,
	send_nf_1 []byte,
	send_nf_2 []byte,
	cm_1 []byte,
	cm_2 []byte) bool {
	return true
}

func ProveShielding(rho []byte, pk []byte, value uint64) []byte {
	toReturn := make([]byte, 584)

	return toReturn
}

func VerifyShielding(proof []byte, send_nf []byte, cm []byte, value uint64) bool {
	return true
}

func ProveUnshielding(rho []byte,
	sk []byte,
	value uint64,
	tree_position uint64,
	authentication_path [][]byte) []byte {
	toReturn := make([]byte, 584)

	return toReturn
}

func VerifyUnshielding(proof []byte, spend_nf []byte, rt []byte, value uint64) bool {

	return true

}
