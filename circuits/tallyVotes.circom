pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/mux1.circom";
include "./lib/hasherPoseidon.circom";
include "./lib/hasherSha256.circom";
include "./lib/messageHasher.circom";
include "./lib/messageToCommand.circom";
include "./lib/privToPubKey.circom";
include "./lib/unpackVoteInfo.circom";
include "./trees/checkRoot.circom";
include "./trees/incrementalQuinTree.circom";

template TallyVotes(
    userTreeDepth,
    batchSize,
    voteOptionTreeDepth
) {
    var TREE_ARITY = 5;

    var MSG_LENGTH = 4;

    var numVoteOptions = TREE_ARITY ** voteOptionTreeDepth;

    signal input inputHash;

    signal input userRoot;

    signal input voiceCreditPerUser;

    signal input maxVoteOptions;

    signal input batchStartHash;

    signal input batchEndHash;

    // The messages
    signal input msgs[batchSize][MSG_LENGTH];

    // The ECDH public key per message
    signal input encPubKeys[batchSize][2];

    // The coordinator's private key
    signal input coordPrivKey;

    // The cooordinator's public key from the contract.
    signal input coordPubKey[2];

    component derivedPubKey = PrivToPubKey();
    derivedPubKey.privKey <== coordPrivKey;
    derivedPubKey.pubKey[0] === coordPubKey[0];
    derivedPubKey.pubKey[1] === coordPubKey[1];

    signal input currentInaFlagSetRootPair[2];

    signal input currentInaFlagPathElementsPair[2][userTreeDepth][4];

    signal input newInaFlagSetRootPair[2];

    signal input inaFlagIndex[batchSize];

    signal input commandValid[batchSize];

    signal input votes[batchSize][numVoteOptions];

    signal input currentResults[numVoteOptions];

    signal input currentCommitment;
    signal input currentSalt;

    signal input newCommitment;
    signal input newSalt;


    // STEP 1 -----------------------------------------------------------------
    // Ensure the processing sequence.

    component messageHashers[batchSize];
    component isEmptyMsg[batchSize];
    component muxes[batchSize];

    signal msgHashChain[batchSize + 1];
    msgHashChain[0] <== batchStartHash;

    // msgChainHash[m] = isEmptyMessage
    //   ? msgChainHash[m - 1]
    //   : hash( hash(msg[m]) , msgChainHash[m - 1] )

    for (var i = 0; i < batchSize; i ++) {
        messageHashers[i] = MessageHasher();
        for (var j = 0; j < MSG_LENGTH; j ++) {
            messageHashers[i].in[j] <== msgs[i][j];
        }
        messageHashers[i].encPubKey[0] <== encPubKeys[i][0];
        messageHashers[i].encPubKey[1] <== encPubKeys[i][1];
        messageHashers[i].prevHash <== msgHashChain[i];

        isEmptyMsg[i] = IsZero();
        isEmptyMsg[i].in <== encPubKeys[i][0];

        muxes[i] = Mux1();
        muxes[i].s <== isEmptyMsg[i].out;
        muxes[i].c[0] <== messageHashers[i].hash;
        muxes[i].c[1] <== msgHashChain[i];

        msgHashChain[i + 1] <== muxes[i].out;
    }
    msgHashChain[batchSize] === batchEndHash;


    // STEP 2 -----------------------------------------------------------------
    // Decrypt all voting messages.

    component commands[batchSize];
    for (var i = 0; i < batchSize; i ++) {
        commands[i] = MessageToCommand();
        commands[i].encPrivKey <== coordPrivKey;
        commands[i].encPubKey[0] <== encPubKeys[i][0];
        commands[i].encPubKey[1] <== encPubKeys[i][1];
        for (var j = 0; j < MSG_LENGTH; j ++) {
            commands[i].message[j] <== msgs[i][j];
        }
    }


    // STEP 3 -----------------------------------------------------------------
    // Check the validity of the command.

    component transformers[batchSize];

    signal inaFlagSetRootPair[batchSize + 1][2];
    inaFlagSetRootPair[0][0] <== currentInaFlagSetRootPair[0];
    inaFlagSetRootPair[0][1] <== currentInaFlagSetRootPair[1];

    for (var i = 0; i < batchSize; i ++) {
        transformers[i] = InaFlagSetTransformer(userTreeDepth);

        transformers[i].inaFlagSetRoot <== inaFlagSetRootPair[i][0];
        transformers[i].seenInaFlagSetRoot <== inaFlagSetRootPair[i][1];
        for (var j = 0; j < userTreeDepth; j ++) {
            for (var k = 0; k < 4; k ++) {
                transformers[i].inaFlagPathElements[j][k] <== currentInaFlagPathElementsPair[0][j][k];
                transformers[i].seenFlagPathElements[j][k] <== currentInaFlagPathElementsPair[1][j][k];
            }
        }
        transformers[i].inaFlagIndex <== inaFlagIndex[i];
        transformers[i].inactiveFlag <== commands[i].inactiveFlag;
        transformers[i].commandValid <== commandValid[i];

        inaFlagSetRootPair[i + 1][0] <== transformers[i].newInaFlagSetRoot;
        inaFlagSetRootPair[i + 1][1] <== transformers[i].newSeenFlagSetRoot;
    }

    inaFlagSetRootPair[batchSize][0] === newInaFlagSetRootPair[0];
    inaFlagSetRootPair[batchSize][1] === newInaFlagSetRootPair[1];


    // STEP 4 -----------------------------------------------------------------
    // Calculation results.

    var MAX_VOTES_POWER = 10 ** 48;
    component newResults[numVoteOptions];
    signal realVotes[batchSize][numVoteOptions];
    for (var i = 0; i < numVoteOptions; i ++) {
        newResults[i] = CalculateTotal(batchSize + 1);
        newResults[i].nums[batchSize] <== currentResults[i];
        for (var j = 0; j < batchSize; j ++) {
            realVotes[j][i] <== votes[j][i] * commandValid[j];
            newResults[i].nums[j] <== realVotes[j][i] * (realVotes[j][i] + MAX_VOTES_POWER);
        }
    }


    // STEP 5 -----------------------------------------------------------------
    // Verify the current and new commitment.

    component voteRoots[batchSize];
    for (var i = 0; i < batchSize; i ++) {
        voteRoots[i] = QuinCheckRoot(voteOptionTreeDepth);
        for (var j = 0; j < numVoteOptions; j ++) {
            voteRoots[i].leaves[j] <== votes[i][j];
        }
        voteRoots[i].root === commands[i].votesRoot;
    }

    component resultRoot = QuinCheckRoot(voteOptionTreeDepth);
    component newResultRoot = QuinCheckRoot(voteOptionTreeDepth);
    for (var i = 0; i < numVoteOptions; i ++) {
        resultRoot.leaves[i] <== currentResults[i];
        newResultRoot.leaves[i] <== newResults[i].sum;
    }

    component currentCommitmentHasher = Hasher5();
    currentCommitmentHasher.in[0] <== currentInaFlagSetRootPair[0];
    currentCommitmentHasher.in[1] <== currentInaFlagSetRootPair[1];
    currentCommitmentHasher.in[2] <== resultRoot.root;
    currentCommitmentHasher.in[3] <== 0;
    currentCommitmentHasher.in[4] <== currentSalt;

    currentCommitmentHasher.hash === currentCommitment;

    component newCommitmentHasher = Hasher5();
    newCommitmentHasher.in[0] <== newInaFlagSetRootPair[0];
    newCommitmentHasher.in[1] <== newInaFlagSetRootPair[1];
    newCommitmentHasher.in[2] <== newResultRoot.root;
    newCommitmentHasher.in[3] <== 0;
    newCommitmentHasher.in[4] <== newSalt;

    newCommitmentHasher.hash === newCommitment;


    // STEP 6 -----------------------------------------------------------------
    // Check input hash.

    component paramsHasher = Hasher5();
    paramsHasher.in[0] <== userRoot;
    paramsHasher.in[1] <== coordPubKey[0];
    paramsHasher.in[2] <== coordPubKey[1];
    paramsHasher.in[3] <== voiceCreditPerUser;
    paramsHasher.in[4] <== maxVoteOptions;

    component inputHasher = Sha256Hasher5();
    inputHasher.in[0] <== paramsHasher.hash;
    inputHasher.in[1] <== batchStartHash;
    inputHasher.in[2] <== batchEndHash;
    inputHasher.in[3] <== currentCommitment;
    inputHasher.in[4] <== newCommitment;

    inputHash === inputHasher.hash;
}

template InaFlagSetTransformer(
    userTreeDepth
) {
    signal input inaFlagSetRoot;

    signal input seenInaFlagSetRoot;

    signal input inaFlagPathElements[userTreeDepth][4];

    signal input seenFlagPathElements[userTreeDepth][4];

    signal input inaFlagIndex;

    signal input inactiveFlag;

    // true or false
    signal input commandValid;

    signal output newInaFlagSetRoot;

    signal output newSeenFlagSetRoot;

    commandValid * (commandValid - 1) === 0;

    component inaFlagPathIndices = QuinGeneratePathIndices(userTreeDepth);
    inaFlagPathIndices.in <== inaFlagIndex;

    component inaFlagLeaf = Mux1();
    inaFlagLeaf.s <== commandValid;
    inaFlagLeaf.c[0] <== inactiveFlag;
    inaFlagLeaf.c[1] <== 0;

    component inaFlagQle = QuinLeafExists(userTreeDepth);
    inaFlagQle.leaf <== inaFlagLeaf.out;
    inaFlagQle.root <== inaFlagSetRoot;

    component seenFlagQle = QuinLeafExists(userTreeDepth);
    seenFlagQle.leaf <== inactiveFlag - inaFlagLeaf.out;
    seenFlagQle.root <== seenInaFlagSetRoot;

    component newInaFlagRoot = QuinTreeInclusionProof(userTreeDepth);
    newInaFlagRoot.leaf <== 0;

    component newSeenFlagRoot = QuinTreeInclusionProof(userTreeDepth);
    newSeenFlagRoot.leaf <== inactiveFlag;

    for (var i = 0; i < userTreeDepth; i ++) {
        inaFlagQle.path_index[i] <== inaFlagPathIndices.out[i];
        seenFlagQle.path_index[i] <== inaFlagPathIndices.out[i];
    
        newInaFlagRoot.path_index[i] <== inaFlagPathIndices.out[i];
        newSeenFlagRoot.path_index[i] <== inaFlagPathIndices.out[i];

        for (var j = 0; j < 4; j ++) {
            inaFlagQle.path_elements[i][j] <== inaFlagPathElements[i][j];
            seenFlagQle.path_elements[i][j] <== seenFlagPathElements[i][j];

            newInaFlagRoot.path_elements[i][j] <== inaFlagPathElements[i][j];
            newSeenFlagRoot.path_elements[i][j] <== seenFlagPathElements[i][j];
        }
    }

    newInaFlagSetRoot <== newInaFlagRoot.root;
    newSeenFlagSetRoot <== newSeenFlagRoot.root;
}
