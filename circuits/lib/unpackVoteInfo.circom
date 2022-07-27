pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "./calculateTotal.circom";

/*
 * Converts a field element (253 bits) to 10 * (8 + 16) bits output elements
 */
template UnpackVoteInfo() {
    signal input in;
    signal output voteOption[10];
    signal output votes[10];
    signal output totalVotes;

    // Convert input to bits
    component inputBits = Num2Bits_strict();
    inputBits.in <== in;

    component outputOptions[10];
    component outputVotes[10];
    component caculateTotalVotes = CalculateTotal(10);
    for (var i = 0; i < 10; i ++) {
        outputOptions[i] = Bits2Num(8);
        outputVotes[i] = Bits2Num(16);
        for (var j = 0; j < 8; j ++) {
            outputOptions[i].in[j] <== inputBits.out[((9 - i) * 24) + j];
        }
        for (var j = 0; j < 16; j ++) {
            outputVotes[i].in[j] <== inputBits.out[((9 - i) * 24) + 8 + j];
        }
        voteOption[i] <== outputOptions[i].out;
        votes[i] <== outputVotes[i].out;
        caculateTotalVotes.nums[i] <== outputVotes[i].out;
    }

    totalVotes <== caculateTotalVotes.sum;
}
