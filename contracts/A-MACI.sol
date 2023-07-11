// SPDX-License-Identifier: MIT
pragma solidity >0.8.6 <0.9.0;

import {DomainObjs} from "./DomainObjs.sol";
import {Ownable} from "./Ownable.sol";
import {VkRegistry} from "./VkRegistry.sol";
import {Verifier} from "./crypto/Verifier.sol";
import {SnarkCommon} from "./crypto/SnarkCommon.sol";
import {SignUpGatekeeper} from "./gatekeepers/SignUpGatekeeper.sol";
import {QuinaryTreeRoot} from "./store/QuinaryTreeRoot.sol";

// import { SnarkConstants } from "./crypto/SnarkConstants.sol"; // SnarkConstants -> Hasher -> DomainObjs

contract AMACI is DomainObjs, SnarkCommon, Ownable {
    struct MaciParameters {
        uint256 stateTreeDepth;
        // uint256 intStateTreeDepth;
        uint256 messageBatchSize;
        uint256 voteOptionTreeDepth;
    }

    enum Period {
        Pending,
        SingingUp,
        Voting,
        Tallying,
        Ended
    }

    uint256 private constant STATE_TREE_ARITY = 5;

    PubKey public coordinator;

    SignUpGatekeeper public gateKeeper;

    // The verifying key registry. There may be multiple verifying keys stored
    // on chain, and Poll contracts must select the correct VK based on the
    // circuit's compile-time parameters, such as tree depths and batch sizes.
    VkRegistry public vkRegistry;

    // Verify the results at the final counting stage.
    QuinaryTreeRoot public qtrLib;

    Verifier public verifier;

    MaciParameters public parameters;

    Period public period;

    mapping(address => uint256) public stateIdxInc;
    // mapping(uint256 => uint256) public voiceCreditBalance;
    uint256 public voiceCreditBalance;

    uint256 public numSignUps;
    uint256 public maxVoteOptions;

    uint256 public stateRootWithParams;

    uint256 public inactiveFlagSetRoot;

    uint256 public msgChainLength;
    mapping(uint256 => uint256) public msgHashes;
    uint256 public currentStateCommitment;
    uint256 private _processedMsgCount;

    mapping(uint256 => uint256) public result;

    uint256 private _maxLeavesCount;
    uint256 private _leafIdx0;
    uint256[8] private _zeros;
    /*
     *  length: (5 ** (depth + 1) - 1) / 4
     *
     *  hashes(leaves) at depth D: nodes[n]
     *  n => [ (5**D-1)/4 , (5**(D+1)-1)/4 )
     */
    mapping(uint256 => uint256) private _nodes;

    uint256 public totalResult;

    event SignUp(uint256 indexed _stateIdx, uint256 _userPubKey);
    event Vote(uint256 indexed _msgIdx, uint256[6] _msgAndEncPubKey);

    modifier atPeriod(Period _p) {
        require(_p == period, "MACI: period error");
        _;
    }

    function init(
        address _admin,
        uint256 _voiceCreditBalance,
        VkRegistry _vkRegistry,
        QuinaryTreeRoot _qtrLib,
        Verifier _verifier,
        SignUpGatekeeper _gateKeeper,
        MaciParameters memory _parameters,
        PubKey memory _coordinator
    ) public atPeriod(Period.Pending) {
        admin = _admin;
        voiceCreditBalance = _voiceCreditBalance;
        vkRegistry = _vkRegistry;
        qtrLib = _qtrLib;
        verifier = _verifier;
        gateKeeper = _gateKeeper;
        parameters = _parameters;
        coordinator = _coordinator;

        // _stateTree.init();
        _maxLeavesCount = 5**_parameters.stateTreeDepth;
        _leafIdx0 = (_maxLeavesCount - 1) / 4;

        _zeros[0] = 0;
        _zeros[1] = 14655542659562014735865511769057053982292279840403315552050801315682099828156;
        _zeros[2] = 19261153649140605024552417994922546473530072875902678653210025980873274131905;
        _zeros[3] = 21526503558325068664033192388586640128492121680588893182274749683522508994597;
        _zeros[4] = 20017764101928005973906869479218555869286328459998999367935018992260318153770;
        _zeros[5] = 16998355316577652097112514691750893516081130026395813155204269482715045879598;
        _zeros[6] = 2612442706402737973181840577010736087708621987282725873936541279764292204086;
        // _zeros[7] = 17716535433480122581515618850811568065658392066947958324371350481921422579201;
        // _zeros[8] = 17437916409890180001398333108882255895598851862997171508841759030332444017770;

        period = Period.SingingUp;
    }

    function setParameters(MaciParameters memory _parameters) public onlyOwner {
        parameters = _parameters;
    }

    function hashMessageAndEncPubKey(
        uint256[6] memory _msgAndEncPubKey,
        uint256 _prevHash
    ) public pure returns (uint256) {
        uint256[5] memory m;
        m[0] = _msgAndEncPubKey[0];
        m[1] = _msgAndEncPubKey[1];
        m[2] = _msgAndEncPubKey[2];
        m[3] = _msgAndEncPubKey[3];
        m[4] = 0;

        uint256[5] memory n;
        n[0] = 0;
        n[1] = 0;
        n[2] = _msgAndEncPubKey[4];
        n[3] = _msgAndEncPubKey[5];
        n[4] = _prevHash;

        return hash2([hash5(m), hash5(n)]);
    }

    function stateOf(address _signer) public view returns (uint256, uint256) {
        uint256 ii = stateIdxInc[_signer];
        require(ii >= 1);
        uint256 stateIdx = ii - 1;
        return (stateIdx, voiceCreditBalance);
    }

    function signUp(uint256 _pubKey, bytes memory _data)
        public
        atPeriod(Period.SingingUp)
    {
        require(numSignUps < _maxLeavesCount, "full");
        require(
            _pubKey < SNARK_SCALAR_FIELD,
            "MACI: _pubKey values should be less than the snark scalar field"
        );

        bool valid = gateKeeper.register(msg.sender, _data);

        require(valid, "401");

        uint256 stateLeaf = _pubKey;
        uint256 stateIndex = numSignUps;
        _stateEnqueue(stateLeaf);
        numSignUps++;

        stateIdxInc[msg.sender] = numSignUps;

        emit SignUp(stateIndex, _pubKey);
    }

    function setPeriod(Period _p)
        external
        onlyOwner
    {
        period = _p;
    }

    function stopSingUp(uint256 _maxVoteOptions)
        external
        onlyOwner
        atPeriod(Period.SingingUp)
    {
        maxVoteOptions = _maxVoteOptions;

        uint256[5] memory inputs;
        inputs[0] = _stateRoot();
        inputs[1] = coordinator.x;
        inputs[2] = coordinator.y;
        inputs[3] = voiceCreditBalance;
        inputs[4] = _maxVoteOptions;
        stateRootWithParams = hash5(inputs);

        period = Period.Voting;
    }

    function voting(
        uint256[6] memory _msgAndEncPubKey,
        uint256[8] memory _proof
    ) external {
        uint256[] memory input = new uint256[](7);
        input[0] = stateRootWithParams;
        for (uint256 i = 0; i < 6; i++) {
            input[i + 1] = _msgAndEncPubKey[i];
        }

        uint256 inputHash = uint256(sha256(abi.encodePacked(input))) %
            SNARK_SCALAR_FIELD;

        VerifyingKey memory vk = vkRegistry.getVoteVk(
            parameters.stateTreeDepth,
            parameters.voteOptionTreeDepth
        );

        bool isValid = verifier.verify(_proof, vk, inputHash);
        require(isValid, "invalid proof");

        msgHashes[msgChainLength + 1] = hashMessageAndEncPubKey(
            _msgAndEncPubKey,
            msgHashes[msgChainLength]
        );

        emit Vote(msgChainLength, _msgAndEncPubKey);
        msgChainLength++;
    }

    function stopVotingPeriod(uint256 inSetRoot, uint256[8] memory _proof)
        public
        onlyOwner
        atPeriod(Period.Voting)
    {
        period = Period.Tallying;

        VerifyingKey memory vk = vkRegistry.getIsetVk(
            parameters.stateTreeDepth
        );

        bool isValid = verifier.verify(_proof, vk, inSetRoot);
        require(isValid, "invalid proof");

        inactiveFlagSetRoot = inSetRoot;

        uint256[5] memory inputs;
        inputs[0] = inSetRoot;
        inputs[1] = _zeros[parameters.stateTreeDepth];
        inputs[2] = _zeros[parameters.voteOptionTreeDepth];
        inputs[3] = 0;
        inputs[4] = 0;

        currentStateCommitment = hash5(inputs);
    }

    // Transfer state root according to message queue.
    function processTally(uint256 newStateCommitment, uint256[8] memory _proof)
        public
        atPeriod(Period.Tallying)
    {
        require(
            _processedMsgCount < msgChainLength,
            "all messages have been processed"
        );

        uint256 batchSize = parameters.messageBatchSize;

        uint256[] memory input = new uint256[](5);
        input[0] = stateRootWithParams;

        uint256 batchStartIndex = ((msgChainLength - _processedMsgCount - 1) /
            batchSize) * batchSize;
        uint256 batchEndIdx = batchStartIndex + batchSize;
        if (batchEndIdx > msgChainLength) {
            batchEndIdx = msgChainLength;
        }
        input[2] = msgHashes[batchStartIndex]; // batchStartHash
        input[3] = msgHashes[batchEndIdx]; // batchEndHash

        input[4] = currentStateCommitment;
        input[5] = newStateCommitment;

        uint256 inputHash = uint256(sha256(abi.encodePacked(input))) %
            SNARK_SCALAR_FIELD;

        VerifyingKey memory vk = vkRegistry.getTallyVk(
            parameters.stateTreeDepth,
            parameters.voteOptionTreeDepth,
            batchSize
        );

        bool isValid = verifier.verify(_proof, vk, inputHash);
        require(isValid, "invalid proof");

        // Proof success, update commitment and progress.
        currentStateCommitment = newStateCommitment;
        _processedMsgCount += batchEndIdx - batchStartIndex;
    }

    function stopTallyingPeriod(uint256[] memory _results, uint256 _salt)
        public
        atPeriod(Period.Tallying)
    {
        require(_processedMsgCount == msgChainLength);
        require(_results.length <= maxVoteOptions);

        uint256 resultsRoot = qtrLib.rootOf(
            parameters.voteOptionTreeDepth,
            _results
        );

        uint256 tallyCommitment = hash5(
            [
                _zeros[parameters.stateTreeDepth],
                inactiveFlagSetRoot,
                resultsRoot,
                0,
                _salt
            ]
        );

        require(tallyCommitment == currentStateCommitment);

        uint256 sum = 0;
        for (uint256 i = 0; i < _results.length; i++) {
            result[i] = _results[i];
            sum += _results[i];
        }
        totalResult = sum;

        period = Period.Ended;
    }

    // function stopTallyingPeriodWithoutResults()
    //     public
    //     onlyOwner
    //     atPeriod(Period.Tallying)
    // {
    //     require(_processedMsgCount == msgChainLength);
    //     period = Period.Ended;
    // }

    function _stateRoot() public view returns (uint256) {
        return _nodes[0];
    }

    function _stateEnqueue(uint256 _leaf) private {
        uint256 leafIdx = _leafIdx0 + numSignUps;
        _nodes[leafIdx] = _leaf;
        _stateUpdateAt(leafIdx);
    }

    function _stateUpdateAt(uint256 _index) private {
        require(_index >= _leafIdx0, "must update from height 0");

        uint256 idx = _index;
        uint256 height = 0;
        while (idx > 0) {
            uint256 parentIdx = (idx - 1) / 5;
            uint256 childrenIdx0 = parentIdx * 5 + 1;

            uint256 zero = _zeros[height];

            uint256[5] memory inputs;
            for (uint256 i = 0; i < 5; i++) {
                uint256 child = _nodes[childrenIdx0 + i];
                if (child == 0) {
                    child = zero;
                }
                inputs[i] = child;
            }
            _nodes[parentIdx] = hash5(inputs);

            height++;
            idx = parentIdx;
        }
    }
}
