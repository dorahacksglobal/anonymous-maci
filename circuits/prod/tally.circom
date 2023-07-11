pragma circom 2.0.0;

include "../tallyVotes.circom";

// userTreeDepth
// batchSize
// voteOptionTreeDepth

component main {
  public [
    inputHash
  ]
} = TallyVotes(5, 25, 3);
