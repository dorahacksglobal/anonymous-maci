pragma circom 2.0.0;

include "../userVote.circom";

// userTreeDepth
// voteOptionTreeDepth

component main {
  public [
    inputHash
  ]
} = UserVote(5, 3);
