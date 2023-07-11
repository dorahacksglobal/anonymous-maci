// SPDX-License-Identifier: MIT
pragma solidity >0.8.6 <0.9.0;

interface SignUpGatekeeper {
    function setMaciInstance(address _maci) external;

    function register(address _user, bytes memory _data)
        external
        returns (bool);
}
