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
	"encoding/hex"
	"fmt"
)

func NewShielding() *Shielding {
	toReturn := &Shielding{}
	toReturn.Snark = make([]byte, ProofSize)
	toReturn.Commitment = make([]byte, HashSize)
	toReturn.SendNullifier = make([]byte, HashSize)

	return toReturn
}

func NewVerifyShieldingRequest() *VerifyShieldingRequest {
	toReturn := &VerifyShieldingRequest{}
	toReturn.Shielding = NewShielding()

	return toReturn
}

func NewVerifyUnshieldingRequest() *VerifyUnshieldingRequest {
	toReturn := &VerifyUnshieldingRequest{}
	toReturn.Snark = make([]byte, ProofSize)
	toReturn.TreeRoot = make([]byte, HashSize)
	toReturn.SpendNullifier = make([]byte, HashSize)

	return toReturn
}

func NewShieldedTransfer() *ShieldedTransfer {
	toReturn := &ShieldedTransfer{}
	toReturn.Snark = make([]byte, ProofSize)
	toReturn.SendNullifiers = make([][]byte, 2)
	toReturn.SpendNullifiers = make([][]byte, 2)
	toReturn.Commitments = make([][]byte, 2)

	for i := 0; i < 2; i++ {
		toReturn.SendNullifiers[i] = make([]byte, HashSize)
		toReturn.SpendNullifiers[i] = make([]byte, HashSize)
		toReturn.Commitments[i] = make([]byte, HashSize)
	}

	return toReturn
}

func NewVerifyShieldedTransferRequest() *VerifyShieldedTransferRequest {
	toReturn := &VerifyShieldedTransferRequest{}
	toReturn.TreeRoot = make([]byte, HashSize)
	toReturn.ShieldedTransfer = NewShieldedTransfer()

	return toReturn
}

// message Unshielding {
// 	bytes snark = 1;
// 	bytes spendNullifier = 2; // nullifies the unshielded input note
// 	bytes sendNullifier = 3; // ensures rho (randomness) isn't re-used
// }

func (unshielding *Unshielding) DebugString() string {
	return fmt.Sprintf("%18s: %s\n%18s: %s\n%18s: %s\n",
		"snark",
		hex.EncodeToString(unshielding.Snark),
		"spendNullifier",
		hex.EncodeToString(unshielding.SpendNullifier),
		"sendNullifier",
		hex.EncodeToString(unshielding.SendNullifier),
	)
}
