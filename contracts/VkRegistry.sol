// SPDX-License-Identifier: MIT
pragma solidity >0.8.6 <0.9.0;

import {SnarkCommon} from "./crypto/SnarkCommon.sol";
import {Ownable} from "./Ownable.sol";

/*
 * Stores verifying keys for the circuits.
 * Each circuit has a signature which is its compile-time constants represented
 * as a uint256.
 */
contract VkRegistry is Ownable, SnarkCommon {
    mapping(uint256 => VerifyingKey) internal voteVks;
    mapping(uint256 => VerifyingKey) internal isetVks;
    mapping(uint256 => VerifyingKey) internal tallyVks;

    function genVoteVkSig(uint256 _stateTreeDepth, uint256 _voteOptionTreeDepth)
        public
        pure
        returns (uint256)
    {
        return (_stateTreeDepth << 64) + _voteOptionTreeDepth;
    }

    function genTallyVkSig(
        uint256 _stateTreeDepth,
        uint256 _voteOptionTreeDepth,
        uint256 _messageBatchSize
    ) public pure returns (uint256) {
        return
            (_messageBatchSize << 128) +
            (_stateTreeDepth << 64) +
            _voteOptionTreeDepth;
    }

    function setVerifyingKeys(
        uint256 _stateTreeDepth,
        uint256 _voteOptionTreeDepth,
        uint256 _messageBatchSize,
        VerifyingKey memory _voteVk,
        VerifyingKey memory _tallyVk,
        VerifyingKey memory _isetVk
    ) public onlyOwner {
        uint256 voteVkSig = genVoteVkSig(_stateTreeDepth, _voteOptionTreeDepth);

        uint256 tallyVkSig = genTallyVkSig(
            _stateTreeDepth,
            _voteOptionTreeDepth,
            _messageBatchSize
        );

        uint256 isetVkSig = _stateTreeDepth;

        VerifyingKey storage voteVk = voteVks[voteVkSig];
        voteVk.alpha1 = _voteVk.alpha1;
        voteVk.beta2 = _voteVk.beta2;
        voteVk.gamma2 = _voteVk.gamma2;
        voteVk.delta2 = _voteVk.delta2;

        delete voteVk.ic;
        for (uint8 i = 0; i < _voteVk.ic.length; i++) {
            voteVk.ic.push(_voteVk.ic[i]);
        }

        VerifyingKey storage isetVk = isetVks[isetVkSig];
        isetVk.alpha1 = _isetVk.alpha1;
        isetVk.beta2 = _isetVk.beta2;
        isetVk.gamma2 = _isetVk.gamma2;
        isetVk.delta2 = _isetVk.delta2;

        delete isetVk.ic;
        for (uint8 i = 0; i < _isetVk.ic.length; i++) {
            isetVk.ic.push(_isetVk.ic[i]);
        }

        VerifyingKey storage tallyVk = tallyVks[tallyVkSig];
        tallyVk.alpha1 = _tallyVk.alpha1;
        tallyVk.beta2 = _tallyVk.beta2;
        tallyVk.gamma2 = _tallyVk.gamma2;
        tallyVk.delta2 = _tallyVk.delta2;

        delete tallyVk.ic;
        for (uint8 i = 0; i < _tallyVk.ic.length; i++) {
            tallyVk.ic.push(_tallyVk.ic[i]);
        }
    }

    function getVoteVk(uint256 _stateTreeDepth, uint256 _voteOptionTreeDepth)
        public
        view
        returns (VerifyingKey memory)
    {
        uint256 sig = genVoteVkSig(_stateTreeDepth, _voteOptionTreeDepth);

        return voteVks[sig];
    }

    function getIsetVk(uint256 _stateTreeDepth)
        public
        view
        returns (VerifyingKey memory)
    {
        uint256 sig = _stateTreeDepth;

        return isetVks[sig];
    }

    function getTallyVk(
        uint256 _stateTreeDepth,
        uint256 _voteOptionTreeDepth,
        uint256 _messageBatchSize
    ) public view returns (VerifyingKey memory) {
        uint256 sig = genTallyVkSig(
            _stateTreeDepth,
            _voteOptionTreeDepth,
            _messageBatchSize
        );

        return tallyVks[sig];
    }
}
