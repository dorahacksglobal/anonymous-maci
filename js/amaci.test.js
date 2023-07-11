const fs = require('fs')
const { eddsa, poseidon, poseidonEncrypt } = require('circom')
const { utils } = require('ethers')
const { stringizing, genKeypair, genEcdhSharedKey } = require('./keypair')
const Tree = require('./tree')

const SNARK_FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

function packVoteInfo(votesInfo, voteOptionTreeDepth) {
  const voteTree = new Tree(5, voteOptionTreeDepth, 0n)

  let voteInfo = 0n
  const votes = new Array(5 ** voteOptionTreeDepth).fill(0)
  for (const vote of votesInfo) {
    voteTree.updateLeaf(vote.option, BigInt(vote.value))
    voteInfo = (voteInfo << 24n) + (BigInt(vote.value) << 8n) + BigInt(vote.option)
    votes[vote.option] = vote.value
  }

  return {
    votes,
    root: voteTree.root,
    info: voteInfo,
  }
}

const cooordinator = genKeypair(10000n)
const user = [
  {
    prikey: 1n,
    salt: 1n,
  },
  {
    prikey: 2n,
    salt: 2n,
  },
]

const userTreeLeaves = user.map((u) => poseidon([u.prikey, u.salt]))

console.log(userTreeLeaves)

// TEST
const genInputs = ({
  userTreeDepth = 2,
  voteOptionTreeDepth = 1,
  voiceCreditPerUser = 1000n,
  maxVoteOptions = 4n,
  userTreeLeaves,
  coordPubKey,
}) => ({
  privateKey,
  salt,
  votesInfo,
  encPrivKey,
}) => {
  const INACTIVE = 5282231170384877125n

  const userTree = new Tree(5, userTreeDepth, 0n)
  let userIndex = 0
  const pubkey = poseidon([privateKey, salt])
  for (let i = 0; i < userTreeLeaves.length; i++) {
    const u = userTreeLeaves[i]

    userTree.updateLeaf(i, u)
    if (pubkey === u) {
      userIndex = i
    }
  }

  const encKey = genKeypair(encPrivKey)

  const params = poseidon([userTree.root, ...coordPubKey, voiceCreditPerUser, maxVoteOptions])

  const packedVoteInfo = packVoteInfo(votesInfo, voteOptionTreeDepth)

  const command = [packedVoteInfo.info, packedVoteInfo.root, poseidon([privateKey, INACTIVE])]
  const message = poseidonEncrypt(command, genEcdhSharedKey(encPrivKey, coordPubKey), 0n)

  const inputHash = BigInt(utils.soliditySha256(
    new Array(7).fill('uint256'),
    stringizing([
      params,
      ...message,
      ...encKey.pubKey,
    ])
  )) % SNARK_FIELD_SIZE
  
  const input = {
    inputHash,
    voiceCreditPerUser,
    maxVoteOptions,
    userRoot: userTree.root,
    userIndex,
    userPathElements: userTree.pathElementOf(userIndex),
    userPrivKey: privateKey,
    userSalt: salt,
    votes: packedVoteInfo.votes,
    coordPubKey,
    message,
    encPrivKey: encKey.formatedPrivKey,
    encPubKey: encKey.pubKey,
  }

  return input
}

const input = genInputs({
  userTreeDepth: 5,
  voteOptionTreeDepth: 3,
  voiceCreditPerUser: 1000n,
  maxVoteOptions: 4n,
  userTreeLeaves,
  coordPubKey: cooordinator.pubKey,
})({
  privateKey: user[0].prikey,
  salt: user[0].salt,
  votesInfo: [
    { option: 0, value: 11 },
    { option: 1, value: 113 },
    { option: 3, value: 7 },
  ],
  encPrivKey: 1234n,
})

// fs.writeFileSync('./input.json', JSON.stringify(stringizing(input), undefined, 2))
