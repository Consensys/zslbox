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

		C.zsl_load_keys()
	})
}

func ProveTransfer(inputRho1 []byte,
	inputSk1 []byte,
	inputValue1 uint64,
	inputTreeIndex1 uint64,
	inputTreePath1 [][]byte,
	inputRho2 []byte,
	inputSk2 []byte,
	inputValue2 uint64,
	inputTreeIndex2 uint64,
	inputTreePath2 [][]byte,
	outputRho1 []byte,
	outputPk1 []byte,
	outputValue1 uint64,
	outputRho2 []byte,
	outputPk2 []byte,
	outputValue2 uint64) []byte {
	toReturn := make([]byte, 584)

	// copy objects (malloc)
	ptrInputRho1 := C.CBytes(inputRho1)
	ptrInputRho2 := C.CBytes(inputRho2)
	ptrInputSk1 := C.CBytes(inputSk1)
	ptrInputSk2 := C.CBytes(inputSk2)
	ptrInputTreePath1 := C.CBytes(parseTreePath(inputTreePath1))
	ptrInputTreePath2 := C.CBytes(parseTreePath(inputTreePath2))

	ptrOutputPk1 := C.CBytes(outputPk1)
	ptrOutputPk2 := C.CBytes(outputPk2)
	ptrOutputRho1 := C.CBytes(outputRho1)
	ptrOutputRho2 := C.CBytes(outputRho2)

	defer func() {
		C.free(ptrInputRho1)
		C.free(ptrInputRho2)
		C.free(ptrInputSk1)
		C.free(ptrInputSk2)
		C.free(ptrOutputPk1)
		C.free(ptrOutputPk2)
		C.free(ptrOutputRho1)
		C.free(ptrOutputRho2)
		C.free(ptrInputTreePath1)
		C.free(ptrInputTreePath2)
	}()

	C.zsl_prove_transfer(ptrInputRho1,
		ptrInputSk1,
		C.uint64_t(inputValue1),
		C.uint64_t(inputTreeIndex1),
		ptrInputTreePath1,
		ptrInputRho2,
		ptrInputSk2,
		C.uint64_t(inputValue2),
		C.uint64_t(inputTreeIndex2),
		ptrInputTreePath2,
		ptrOutputRho1,
		ptrOutputPk1,
		C.uint64_t(outputValue1),
		ptrOutputRho2,
		ptrOutputPk2,
		C.uint64_t(outputValue2),
		unsafe.Pointer(&toReturn[0]))

	return toReturn
}

func ProveShielding(rho []byte, pk []byte, value uint64) []byte {
	toReturn := make([]byte, 584)

	// copy objects (malloc)
	ptrRho := C.CBytes(rho)
	ptrPk := C.CBytes(pk)

	defer func() {
		C.free(ptrPk)
		C.free(ptrRho)
	}()

	C.zsl_prove_shielding(ptrRho, ptrPk, C.uint64_t(value), unsafe.Pointer(&toReturn[0]))

	return toReturn
}

func ProveUnshielding(rho []byte,
	sk []byte,
	value uint64,
	treeIndex uint64,
	treePath [][]byte) []byte {
	toReturn := make([]byte, 584)

	// copy objects (malloc)
	ptrRho := C.CBytes(rho)
	ptrSk := C.CBytes(sk)
	ptrTreePath := C.CBytes(parseTreePath(treePath))

	defer func() {
		C.free(ptrSk)
		C.free(ptrRho)
		C.free(ptrTreePath)
	}()

	C.zsl_prove_unshielding(ptrRho,
		ptrSk,
		C.uint64_t(value),
		C.uint64_t(treeIndex),
		ptrTreePath,
		unsafe.Pointer(&toReturn[0]))

	return toReturn
}

func VerifyTransfer(proof []byte,
	treeRoot []byte,
	spendNullifier1 []byte,
	spendNullifier2 []byte,
	sendNullifier1 []byte,
	sendNullifier2 []byte,
	commitment1 []byte,
	commitment2 []byte) bool {

	// copy objects (malloc)
	ptrProof := C.CBytes(proof)
	ptrTreeRoot := C.CBytes(treeRoot)

	ptrSendNullifier1 := C.CBytes(sendNullifier1)
	ptrSendNullifier2 := C.CBytes(sendNullifier2)
	ptrSpendNullifier1 := C.CBytes(spendNullifier1)
	ptrSpendNullifier2 := C.CBytes(spendNullifier2)

	ptrCommitment1 := C.CBytes(commitment1)
	ptrCommitment2 := C.CBytes(commitment2)

	defer func() {
		C.free(ptrSendNullifier1)
		C.free(ptrSendNullifier2)
		C.free(ptrSpendNullifier1)
		C.free(ptrSpendNullifier2)
		C.free(ptrCommitment1)
		C.free(ptrCommitment2)
		C.free(ptrProof)
		C.free(ptrTreeRoot)
	}()

	if C.zsl_verify_transfer(ptrProof,
		ptrTreeRoot,
		ptrSpendNullifier1,
		ptrSpendNullifier2,
		ptrSendNullifier1,
		ptrSendNullifier2,
		ptrCommitment1,
		ptrCommitment2) {
		return true
	}
	return false
}

func VerifyShielding(proof []byte, sendNullifier []byte, commitment []byte, value uint64) bool {
	// copy objects (malloc)
	ptrSendNullifier := C.CBytes(sendNullifier)
	ptrCommitment := C.CBytes(commitment)
	ptrProof := C.CBytes(proof)

	defer func() {
		C.free(ptrSendNullifier)
		C.free(ptrCommitment)
		C.free(ptrProof)
	}()

	// call C function
	if C.zsl_verify_shielding(ptrProof, ptrSendNullifier, ptrCommitment, C.uint64_t(value)) {
		return true
	}
	return false
}

func VerifyUnshielding(proof []byte, spendNullifier []byte, treeRoot []byte, value uint64) bool {
	// copy objects (malloc)
	ptrSpendNullifier := C.CBytes(spendNullifier)
	ptrTreeRoot := C.CBytes(treeRoot)
	ptrProof := C.CBytes(proof)

	defer func() {
		C.free(ptrSpendNullifier)
		C.free(ptrTreeRoot)
		C.free(ptrProof)
	}()

	if C.zsl_verify_unshielding(ptrProof, ptrSpendNullifier, ptrTreeRoot, C.uint64_t(value)) {
		return true
	}
	return false
}

func parseTreePath(treePath [][]byte) []byte {
	concatPath := make([]byte, len(treePath)*32)
	for k, v := range treePath {
		i := k * 32
		copy(concatPath[i:i+32], v)
	}
	return concatPath
}
