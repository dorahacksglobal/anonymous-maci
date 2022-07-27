pragma circom 2.0.0;

include "./ecdh.circom";
include "./poseidonDecrypt.circom";

template MessageToCommand() {
    var MSG_LENGTH = 4;
    var CMD_LENGTH = 3;

    signal input message[MSG_LENGTH];
    signal input encPrivKey;
    signal input encPubKey[2];

    signal output voteInfo;
    signal output votesRoot;
    signal output inactiveFlag;

    component ecdh = Ecdh();
    ecdh.privKey <== encPrivKey;
    ecdh.pubKey[0] <== encPubKey[0];
    ecdh.pubKey[1] <== encPubKey[1];

    component decryptor = PoseidonDecryptWithoutCheck(CMD_LENGTH);
    decryptor.key[0] <== ecdh.sharedKey[0];
    decryptor.key[1] <== ecdh.sharedKey[1];
    decryptor.nonce <== 0;
    for (var i = 0; i < MSG_LENGTH; i++) {
        decryptor.ciphertext[i] <== message[i];
    }

    voteInfo <== decryptor.decrypted[0];
    votesRoot <== decryptor.decrypted[1];
    inactiveFlag <== decryptor.decrypted[2];

    signal output sharedKey[2];
    sharedKey[0] <== ecdh.sharedKey[0];
    sharedKey[1] <== ecdh.sharedKey[1];
}
