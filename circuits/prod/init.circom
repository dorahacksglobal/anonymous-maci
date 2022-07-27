pragma circom 2.0.0;

include "../inactiveSet.circom";

// userTreeDepth

component main {
  public [
    root
  ]
} = InactiveSet(5);
