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

// #cgo LDFLAGS: -L${SRCDIR} -lzsl -lm -lstdc++ -lgmp -lgomp -lff
// #include "libsnark/libzsl/zsl.h"
import "C"
import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
)

// Init() is only ever called once
var onceInit sync.Once

func Init(treeDepth uint, keyDir string) {
	onceInit.Do(func() {
		if _, err := os.Stat(keyDir); err != nil {
			panic("key directory doesn't exist or is not mounted")
		}
		transferPath := filepath.Join(keyDir, "transfer.vk")
		shieldingPath := filepath.Join(keyDir, "shielding.vk")
		unshieldingPath := filepath.Join(keyDir, "unshielding.vk")

		C.zsl_initialize(C.uint(treeDepth)) // TODO, pass keyDir there too.

		// when init is called, ensure that keys are found in /keys/...
		if _, err := os.Stat(transferPath); os.IsNotExist(err) {
			fmt.Printf("couldn't find %s, generating...\n", transferPath)
			C.zsl_paramgen_transfer()
		}
		if _, err := os.Stat(shieldingPath); os.IsNotExist(err) {
			fmt.Printf("couldn't find %s, generating...\n", shieldingPath)
			C.zsl_paramgen_shielding()
		}
		if _, err := os.Stat(unshieldingPath); os.IsNotExist(err) {
			fmt.Printf("couldn't find %s, generating...\n", unshieldingPath)
			C.zsl_paramgen_unshielding()
		}
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

	C.zsl_prove_transfer(unsafe.Pointer(&toReturn[0]),
		unsafe.Pointer(&input_rho_1[0]),
		unsafe.Pointer(&input_sk_1[0]),
		C.uint64_t(input_value_1),
		C.uint64_t(input_tree_position_1),
		unsafe.Pointer(&input_authentication_path_1[0][0]),
		unsafe.Pointer(&input_rho_2[0]),
		unsafe.Pointer(&input_sk_2[0]),
		C.uint64_t(input_value_2),
		C.uint64_t(input_tree_position_2),
		unsafe.Pointer(&input_authentication_path_2[0][0]),
		unsafe.Pointer(&output_rho_1[0]),
		unsafe.Pointer(&output_pk_1[0]),
		C.uint64_t(output_value_1),
		unsafe.Pointer(&output_rho_2[0]),
		unsafe.Pointer(&output_pk_2[0]),
		C.uint64_t(output_value_2))

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
	ret := C.zsl_verify_transfer(unsafe.Pointer(&proof[0]),
		unsafe.Pointer(&anchor[0]),
		unsafe.Pointer(&spend_nf_1[0]),
		unsafe.Pointer(&spend_nf_2[0]),
		unsafe.Pointer(&send_nf_1[0]),
		unsafe.Pointer(&send_nf_2[0]),
		unsafe.Pointer(&cm_1[0]),
		unsafe.Pointer(&cm_2[0]))

	if ret {
		return true
	} else {
		return false
	}
}

func ProveShielding(rho []byte, pk []byte, value uint64) []byte {
	toReturn := make([]byte, 584)

	rho_ptr := C.CBytes(rho)
	pk_ptr := C.CBytes(pk)

	C.zsl_prove_shielding(rho_ptr, pk_ptr, C.uint64_t(value), unsafe.Pointer(&toReturn[0]))

	C.free(rho_ptr)
	C.free(pk_ptr)

	return toReturn
}

func VerifyShielding(proof []byte, send_nf []byte, cm []byte, value uint64) bool {
	send_nf_ptr := C.CBytes(send_nf)
	cm_ptr := C.CBytes(cm)
	ret := C.zsl_verify_shielding(unsafe.Pointer(&proof[0]), send_nf_ptr, cm_ptr, C.uint64_t(value))

	C.free(send_nf_ptr)
	C.free(cm_ptr)

	if ret {
		return true
	} else {
		return false
	}
}

func ProveUnshielding(rho []byte,
	sk []byte,
	value uint64,
	tree_position uint64,
	authentication_path [][]byte) []byte {
	toReturn := make([]byte, 584)

	C.zsl_prove_unshielding(unsafe.Pointer(&rho[0]),
		unsafe.Pointer(&sk[0]),
		C.uint64_t(value),
		C.uint64_t(tree_position),
		unsafe.Pointer(&authentication_path[0][0]),
		unsafe.Pointer(&toReturn[0]))

	return toReturn
}

func VerifyUnshielding(proof []byte, spend_nf []byte, rt []byte, value uint64) bool {
	ret := C.zsl_verify_unshielding(unsafe.Pointer(&proof[0]),
		unsafe.Pointer(&spend_nf[0]),
		unsafe.Pointer(&rt[0]),
		C.uint64_t(value))

	if ret {
		return true
	} else {
		return false
	}
}
