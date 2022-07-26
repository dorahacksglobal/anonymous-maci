pragma circom 2.0.0;

include "../userVote.circom";

// userTreeDepth

component main {
  public [
    inputHash
  ]
} = UserVote(6);
