const bip39 = require('bip39');
const { MerkleTree } = require('merkletreejs');
const keccak256 = require('keccak256');
const crypto = require('crypto');
const fs = require('fs');
const roles = require('./roles.json');

const createdKeys = [];

for(let i = 0; i < roles.length; i++){
    let mnemonic = bip39.generateMnemonic();
    let hashedMnemonic = crypto.createHash('md5').update(mnemonic).digest('hex');
    createdKeys.push(roles[i].roleName + '-' + hashedMnemonic);
}

const leafNodes = createdKeys.map(key => keccak256(key));
const merkleTree = new MerkleTree(leafNodes, keccak256, { sortPairs: true });

const rootHash = merkleTree.getHexRoot();
let output = "Root Hash: "+ rootHash + '\n\n';
for(let i = 0; i < leafNodes.length; i++){
    const currentKey = leafNodes[i];
    const hexProof = merkleTree.getHexProof(currentKey);
    output += 
        "========== Hex proof for role "+ roles[i].roleName +" ==========\n\n"+ printHexProof(hexProof) + "\n\n" + 
        "Literal Key: " + createdKeys[i] + "\n\n";
}

if(!fs.existsSync('./output.txt')) fs.appendFileSync('./output.txt',output);
else fs.writeFileSync('./output.txt',output);

console.log('Finished');

function printHexProof(hexProof){
    let print = '[\n'
    for(let i = 0; i < hexProof.length; i++){
        print += '  "'+ hexProof[i] + (i == hexProof.length - 1 ?  '"\n' : '",\n');
    }
    print+=']';
    return print;
}