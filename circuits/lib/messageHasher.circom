pragma circom 2.0.0;

include "./hasherPoseidon.circom";

template MessageHasher() {
    signal input in[4];
    signal input encPubKey[2];
    signal input prevHash;
    signal output hash;

    component hasher = Hasher10();

    for (var i = 0; i < 4; i ++) {
        hasher.in[i] <== in[i];
    }
    hasher.in[4] <== 0;
    hasher.in[5] <== 0;
    hasher.in[6] <== 0;
    hasher.in[7] <== encPubKey[0];
    hasher.in[8] <== encPubKey[1];
    hasher.in[9] <== prevHash;

    hash <== hasher.hash;
}
