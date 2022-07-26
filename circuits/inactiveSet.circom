pragma circom 2.0.0;

include "./trees/checkRoot.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template InactiveSet(
    userTreeDepth
) {
    var totalLeaves = 5 ** userTreeDepth;

    signal input root;

    signal input inactiveFlags[totalLeaves];

    component qcr = QuinCheckRoot(userTreeDepth);
    for (var i = 0; i < totalLeaves; i ++) {
        qcr.leaves[i] <== inactiveFlags[i];
    }

    root === qcr.root;

    component lts[totalLeaves - 1];
    component checkTails[totalLeaves - 1];
    for (var i = 0; i < totalLeaves - 1; i ++) {
        lts[i] = LessThan(252);
        lts[i].in[0] <== inactiveFlags[i];
        lts[i].in[1] <== inactiveFlags[i + 1];

        checkTails[i] = IsZero();
        checkTails[i].in <== inactiveFlags[i + 1];

        1 === lts[i].out * checkTails[i].out;
    }
}
