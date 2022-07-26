pragma circom 2.0.0;

include "./lib/hasherPoseidon.circom";
include "./lib/hasherSha256.circom";
include "./lib/messageToCommand.circom";
include "./lib/unpackVoteInfo.circom";
include "./lib/privToPubKey.circom";
include "./trees/incrementalQuinTree.circom";

template UserVote(
    userTreeDepth
) {
    var TREE_ARITY = 5;

    var MSG_LENGTH = 4;

    // hex('INACTIVE')
    var INACTIVE = 5282231170384877125;

    signal input inputHash;

    signal input voiceCreditPerUser;

    signal input maxVoteOptions;

    signal input userRoot;

    signal input userIndex;

    signal input userPathElements[userTreeDepth][TREE_ARITY - 1];

    // The user's private key
    signal input userPrivKey;

    signal input userSalt;

    signal userInactiveFlag;

    // The cooordinator's public key from the contract.
    signal input coordPubKey[2];

    signal input message[MSG_LENGTH];

    signal input encPrivKey;

    signal input encPubKey[2];

    component derivedPubKey = PrivToPubKey();
    derivedPubKey.privKey <== encPrivKey;
    derivedPubKey.pubKey[0] === encPubKey[0];
    derivedPubKey.pubKey[1] === encPubKey[1];


    // STEP 1 -----------------------------------------------------------------
    // Verify that the user private key exists in the registered user
    // collection.

    component userHasher = HashLeftRight();
    userHasher.left <== userPrivKey;
    userHasher.right <== userSalt;

    component userQle = QuinLeafExists(userTreeDepth);
    component userPathIndices = QuinGeneratePathIndices(userTreeDepth);
    userPathIndices.in <== userIndex;
    userQle.leaf <== userHasher.hash;
    userQle.root <== userRoot;
    for (var i = 0; i < userTreeDepth; i ++) {
        userQle.path_index[i] <== userPathIndices.out[i];
        for (var j = 0; j < TREE_ARITY - 1; j ++) {
            userQle.path_elements[i][j] <== userPathElements[i][j];
        }
    }


    // STEP 2 -----------------------------------------------------------------
    // Verify message signature.
    // Verify that the user's inactive flag is correct.

    component userIAFlagHasher = HashLeftRight();
    userIAFlagHasher.left <== userPrivKey;
    userIAFlagHasher.right <== INACTIVE;

    userInactiveFlag <== userIAFlagHasher.hash;


    component command = MessageToCommand();
    for (var i = 0; i < MSG_LENGTH; i ++) {
        command.message[i] <== message[i];
    }
    command.encPrivKey <== encPrivKey;
    command.encPubKey[0] <== coordPubKey[0];
    command.encPubKey[1] <== coordPubKey[1];

    command.inactiveFlag === userInactiveFlag;


    // STEP 3 -----------------------------------------------------------------
    // Verify that the user's balance is sufficient.

    component voteInfo = unpackVoteInfo();
    voteInfo.in <== command.voteInfo;
    
    component sufficientVoiceCredits = GreaterEqThan(20);
    sufficientVoiceCredits.in[0] <== voiceCreditPerUser;
    sufficientVoiceCredits.in[1] <== voteInfo.totalVotes;
    sufficientVoiceCredits.out === 1;

    component validVoteOptionIndex[10];
    for (var i = 0; i < 10; i ++) {
        validVoteOptionIndex[i] = LessEqThan(8);
        validVoteOptionIndex[i].in[0] <== voteInfo.voteOption[i];
        validVoteOptionIndex[i].in[1] <== maxVoteOptions;

        validVoteOptionIndex[i].out === 1;
    }


    // STEP 5 -----------------------------------------------------------------
    // Check that the input hash is generated correctly.

    component paramsHasher = Hasher5();
    paramsHasher.in[0] <== userRoot;
    paramsHasher.in[1] <== coordPubKey[0];
    paramsHasher.in[2] <== coordPubKey[1];
    paramsHasher.in[3] <== voiceCreditPerUser;
    paramsHasher.in[4] <== maxVoteOptions;

    component inputHasher = Sha256Hasher(7);
    inputHasher.in[0] <== paramsHasher.hash;
    inputHasher.in[1] <== message[0];
    inputHasher.in[2] <== message[1];
    inputHasher.in[3] <== message[2];
    inputHasher.in[4] <== message[3];
    inputHasher.in[5] <== encPubKey[0];
    inputHasher.in[6] <== encPubKey[1];

    inputHash === inputHasher.hash;
}
