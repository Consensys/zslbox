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

#include "zsl.h"

#include <iostream>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/profiling.hpp>
#include <libff/algebra/fields/field_utils.hpp>

using namespace libsnark;
using namespace std;

namespace zsl {
    size_t TREE_DEPTH = 29;

    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vkShielding;
    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vkUnshielding;
    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vkTransfer;
    r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pkShielding;
    r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pkUnshielding;
    r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> pkTransfer;
}

#include "gadgets.cpp"

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

#include <fstream>


void zsl_initialize(uint tree_depth)
{
    zsl::TREE_DEPTH = tree_depth;
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::inhibit_profiling_info = false;
    libff::inhibit_profiling_counters = false;
}


template<typename T>
void saveToFile(string path, T& obj) {
    stringstream ss;
    ss << obj;
    ofstream fh;
    fh.open(path, ios::binary);
    ss.rdbuf()->pubseekpos(0, ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void loadFromFile(string path, T& objIn) {
    stringstream ss;
    ifstream fh(path, ios::binary);
    ss << fh.rdbuf();
    fh.close();
    ss.rdbuf()->pubseekpos(0, ios_base::in);
    ss >> objIn;
}

void zsl_load_keys() {
    loadFromFile("/keys/shielding.vk", zsl::vkShielding);
    loadFromFile("/keys/unshielding.vk", zsl::vkUnshielding);
    loadFromFile("/keys/transfer.vk", zsl::vkTransfer);

    loadFromFile("/keys/shielding.pk", zsl::pkShielding);
    loadFromFile("/keys/unshielding.pk", zsl::pkUnshielding);
    loadFromFile("/keys/transfer.pk", zsl::pkTransfer);
}


bool zsl_verify_shielding(
    void *proof_ptr,
    void *send_nf_ptr,
    void *cm_ptr,
    uint64_t value
)
{
    unsigned char *send_nf = reinterpret_cast<unsigned char *>(send_nf_ptr);
    unsigned char *cm = reinterpret_cast<unsigned char *>(cm_ptr);
    unsigned char *proof = reinterpret_cast<unsigned char *>(proof_ptr);

    vector<unsigned char> proof_v(proof, proof+584);

    stringstream proof_data;
    for (int i = 0; i < 584; i++) {
        proof_data << proof_v[i];
    }

    assert(proof_data.str().size() == 584);

    proof_data.rdbuf()->pubseekpos(0, ios_base::in);

    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof_obj;
    proof_data >> proof_obj;

    auto witness_map = ShieldingCircuit<FieldT>::witness_map(
        vector<unsigned char>(send_nf, send_nf+32),
        vector<unsigned char>(cm, cm+32),
        value
    );

    if (!r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(zsl::vkShielding, witness_map, proof_obj)) {
        return false;
    } else {
        return true;
    }
}

bool zsl_verify_unshielding(
    void *proof_ptr,
    void *spend_nf_ptr,
    void *rt_ptr,
    uint64_t value
)
{
    unsigned char *spend_nf = reinterpret_cast<unsigned char *>(spend_nf_ptr);
    unsigned char *rt = reinterpret_cast<unsigned char *>(rt_ptr);
    unsigned char *proof = reinterpret_cast<unsigned char *>(proof_ptr);

    vector<unsigned char> proof_v(proof, proof+584);

    stringstream proof_data;
    for (int i = 0; i < 584; i++) {
        proof_data << proof_v[i];
    }

    assert(proof_data.str().size() == 584);

    proof_data.rdbuf()->pubseekpos(0, ios_base::in);

    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof_obj;
    proof_data >> proof_obj;

    auto witness_map = UnshieldingCircuit<FieldT>::witness_map(
        vector<unsigned char>(spend_nf, spend_nf+32),
        vector<unsigned char>(rt, rt+32),
        value
    );


    if (!r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(zsl::vkUnshielding, witness_map, proof_obj)) {
        return false;
    } else {
        return true;
    }
}

void zsl_prove_unshielding(
    void *rho_ptr,
    void *pk_ptr,
    uint64_t value,
    uint64_t tree_position,
    void *authentication_path_ptr,
    void *output_proof_ptr
)
{
    unsigned char *rho = reinterpret_cast<unsigned char *>(rho_ptr);
    unsigned char *pk = reinterpret_cast<unsigned char *>(pk_ptr);
    unsigned char *output_proof = reinterpret_cast<unsigned char *>(output_proof_ptr);
    unsigned char *authentication_path = reinterpret_cast<unsigned char *>(authentication_path_ptr);

    protoboard<FieldT> pb;
    UnshieldingCircuit<FieldT> g(pb);
    g.generate_r1cs_constraints();

    vector<vector<bool>> auth_path;
    for (uint i = 0; i < zsl::TREE_DEPTH; i++) {
        auth_path.push_back(convertBytesVectorToVector(vector<unsigned char>(authentication_path + i*32, authentication_path + i*32 + 32)));
    }

    reverse(begin(auth_path), end(auth_path));

    g.generate_r1cs_witness(
        vector<unsigned char>(rho, rho + 32),
        vector<unsigned char>(pk, pk + 32),
        value,
        tree_position,
        auth_path
    );
    // pb.get_constraint_system().swap_AB_if_beneficial(); //TODO check this modification.
    assert(pb.is_satisfied());

    auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(zsl::pkUnshielding, pb.primary_input(), pb.auxiliary_input());

    stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();
    assert(proof_str.size() == 584);

    for (int i = 0; i < 584; i++) {
        output_proof[i] = proof_str[i];
    }
}

void zsl_prove_shielding(
    void *rho_ptr,
    void *pk_ptr,
    uint64_t value,
    void *output_proof_ptr
)
{
    unsigned char *rho = reinterpret_cast<unsigned char *>(rho_ptr);
    unsigned char *pk = reinterpret_cast<unsigned char *>(pk_ptr);
    unsigned char *output_proof = reinterpret_cast<unsigned char *>(output_proof_ptr);


    protoboard<FieldT> pb;
    ShieldingCircuit<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(
        // rho
        vector<unsigned char>(rho, rho + 32),
        // pk
        vector<unsigned char>(pk, pk + 32),
        // value
        value
    );
    // pb.get_constraint_system().swap_AB_if_beneficial(); // TODO check this modification
    assert(pb.is_satisfied());

    auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(zsl::pkShielding, pb.primary_input(), pb.auxiliary_input());
    stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();
    assert(proof_str.size() == 584);
    for (int i = 0; i < 584; i++) {
        output_proof[i] = proof_str[i];
    }
}

bool zsl_verify_transfer(
    void *proof_ptr,
    void *anchor_ptr,
    void *spend_nf_ptr_1,
    void *spend_nf_ptr_2,
    void *send_nf_ptr_1,
    void *send_nf_ptr_2,
    void *cm_ptr_1,
    void *cm_ptr_2
)
{
    unsigned char *anchor = reinterpret_cast<unsigned char *>(anchor_ptr);
    unsigned char *spend_nf_1 = reinterpret_cast<unsigned char *>(spend_nf_ptr_1);
    unsigned char *spend_nf_2 = reinterpret_cast<unsigned char *>(spend_nf_ptr_2);
    unsigned char *send_nf_1 = reinterpret_cast<unsigned char *>(send_nf_ptr_1);
    unsigned char *send_nf_2 = reinterpret_cast<unsigned char *>(send_nf_ptr_2);
    unsigned char *cm_1 = reinterpret_cast<unsigned char *>(cm_ptr_1);
    unsigned char *cm_2 = reinterpret_cast<unsigned char *>(cm_ptr_2);
    unsigned char *proof = reinterpret_cast<unsigned char *>(proof_ptr);

    vector<unsigned char> proof_v(proof, proof+584);

    stringstream proof_data;
    for (int i = 0; i < 584; i++) {
        proof_data << proof_v[i];
    }

    assert(proof_data.str().size() == 584);

    proof_data.rdbuf()->pubseekpos(0, ios_base::in);

    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof_obj;
    proof_data >> proof_obj;

    auto witness_map = TransferCircuit<FieldT>::witness_map(
        vector<unsigned char>(anchor, anchor+32),
        vector<unsigned char>(spend_nf_1, spend_nf_1+32),
        vector<unsigned char>(spend_nf_2, spend_nf_2+32),
        vector<unsigned char>(send_nf_1, send_nf_1+32),
        vector<unsigned char>(send_nf_2, send_nf_2+32),
        vector<unsigned char>(cm_1, cm_1+32),
        vector<unsigned char>(cm_2, cm_2+32)
    );


    if (!r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(zsl::vkTransfer, witness_map, proof_obj)) {
        return false;
    } else {
        return true;
    }
}

void zsl_prove_transfer(
    void *input_rho_ptr_1,
    void *input_pk_ptr_1,
    uint64_t input_value_1,
    uint64_t input_tree_position_1,
    void *input_authentication_path_ptr_1,
    void *input_rho_ptr_2,
    void *input_pk_ptr_2,
    uint64_t input_value_2,
    uint64_t input_tree_position_2,
    void *input_authentication_path_ptr_2,
    void *output_rho_ptr_1,
    void *output_pk_ptr_1,
    uint64_t output_value_1,
    void *output_rho_ptr_2,
    void *output_pk_ptr_2,
    uint64_t output_value_2,
    void *output_proof_ptr
)
{
    unsigned char *output_proof = reinterpret_cast<unsigned char *>(output_proof_ptr);

    unsigned char *input_rho_1 = reinterpret_cast<unsigned char *>(input_rho_ptr_1);
    unsigned char *input_pk_1 = reinterpret_cast<unsigned char *>(input_pk_ptr_1);
    unsigned char *authentication_path_1 = reinterpret_cast<unsigned char *>(input_authentication_path_ptr_1);

    unsigned char *input_rho_2 = reinterpret_cast<unsigned char *>(input_rho_ptr_2);
    unsigned char *input_pk_2 = reinterpret_cast<unsigned char *>(input_pk_ptr_2);
    unsigned char *authentication_path_2 = reinterpret_cast<unsigned char *>(input_authentication_path_ptr_2);

    unsigned char *output_rho_1 = reinterpret_cast<unsigned char *>(output_rho_ptr_1);
    unsigned char *output_pk_1 = reinterpret_cast<unsigned char *>(output_pk_ptr_1);
    unsigned char *output_rho_2 = reinterpret_cast<unsigned char *>(output_rho_ptr_2);
    unsigned char *output_pk_2 = reinterpret_cast<unsigned char *>(output_pk_ptr_2);

    vector<vector<bool>> auth_path_1;
    for (uint i = 0; i < zsl::TREE_DEPTH; i++) {
        auth_path_1.push_back(convertBytesVectorToVector(vector<unsigned char>(authentication_path_1 + i*32, authentication_path_1 + i*32 + 32)));
    }

    reverse(begin(auth_path_1), end(auth_path_1));

    vector<vector<bool>> auth_path_2;
    for (uint i = 0; i < zsl::TREE_DEPTH; i++) {
        auth_path_2.push_back(convertBytesVectorToVector(vector<unsigned char>(authentication_path_2 + i*32, authentication_path_2 + i*32 + 32)));
    }

    reverse(begin(auth_path_2), end(auth_path_2));

    protoboard<FieldT> pb;
    TransferCircuit<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(
        vector<unsigned char>(input_rho_1, input_rho_1 + 32),
        vector<unsigned char>(input_pk_1, input_pk_1 + 32),
        input_value_1,
        input_tree_position_1,
        auth_path_1,
        vector<unsigned char>(input_rho_2, input_rho_2 + 32),
        vector<unsigned char>(input_pk_2, input_pk_2 + 32),
        input_value_2,
        input_tree_position_2,
        auth_path_2,
        vector<unsigned char>(output_rho_1, output_rho_1 + 32),
        vector<unsigned char>(output_pk_1, output_pk_1 + 32),
        output_value_1,
        vector<unsigned char>(output_rho_2, output_rho_2 + 32),
        vector<unsigned char>(output_pk_2, output_pk_2 + 32),
        output_value_2
    );
    // pb.get_constraint_system().swap_AB_if_beneficial(); // TODO check this
    assert(pb.is_satisfied());


    auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(zsl::pkTransfer, pb.primary_input(), pb.auxiliary_input());

    stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();
    assert(proof_str.size() == 584);

    for (int i = 0; i < 584; i++) {
        output_proof[i] = proof_str[i];
    }
}

void zsl_paramgen_transfer()
{
    protoboard<FieldT> pb;
    TransferCircuit<FieldT> g(pb);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    auto crs = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    saveToFile("/keys/transfer.pk", crs.pk);
    saveToFile("/keys/transfer.vk", crs.vk);
}

void zsl_paramgen_shielding()
{
    protoboard<FieldT> pb;
    ShieldingCircuit<FieldT> g(pb);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    auto crs = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    saveToFile("/keys/shielding.pk", crs.pk);
    saveToFile("/keys/shielding.vk", crs.vk);
}

void zsl_paramgen_unshielding()
{
    protoboard<FieldT> pb;
    UnshieldingCircuit<FieldT> g(pb);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    auto crs = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    saveToFile("/keys/unshielding.pk", crs.pk);
    saveToFile("/keys/unshielding.vk", crs.vk);
}
