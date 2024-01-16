import json
import hashlib

def _hash(s):
    return hashlib.sha512(s.encode()).digest().hex()


def bitstr_to_secret(s):
    secret_str = _hash(s)

    # Set aside 2 bytes of the joint secret to use as checksum, then re-hash it
    # to expand entropy back from 496 actual to 512 effective
    secret_str, checksum = secret_str[:-4], secret_str[-4:]
    return _hash(secret_str), checksum


basis_A = open("basis_A.txt").read().splitlines()
basis_B = open("basis_B.txt").read().splitlines()

mes_A = json.load(open("measurement_A.json"))

matching_basis_indices = set()

for idx, (our_basis, their_basis) in enumerate(
    zip(basis_A, basis_B)
):
    if our_basis != their_basis:
        continue
    else:
        matching_basis_indices.add(idx)

# Qubits we measured using the same basis will yield the same outcome, so B can also find this pretty random string
outcome_str = " ".join(
    [str(mes_A[quuid_idx]) for quuid_idx in sorted(matching_basis_indices)]
)

flag_hex = "fcdff210a9791454e699c44fa91d8616eb7bb82e39b1e3152625690791555007681addad8fbdb43a5735d090f97533b7f38b690bd187aab9e6cf33d3838c9a85"

joint_secret, checksum = bitstr_to_secret(outcome_str)

key_bytes = hashlib.sha512(joint_secret.encode()).digest()
flag_bytes = bytes.fromhex(flag_hex)

res = bytes(a ^ b for a, b in zip(flag_bytes, key_bytes))
print(res)
