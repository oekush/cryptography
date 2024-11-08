class MerkleTree {
    constructor(hashes) {
        if (hashes.length === 0) {
            throw new Error("Cannot create a Merkle Tree with no data.");
        }
        this.leaves = hashes.map(h => h); // Store leaf nodes
        this.levels = [this.leaves];      // Store tree levels
        this.buildTree();
    }

    // Build the tree by hashing pairs of nodes level by level
    buildTree() {
        let currentLevel = this.leaves;

        while (currentLevel.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                const left = currentLevel[i];
                const right = currentLevel[i + 1] || left; // Duplicate last node if odd
                const combinedHash = this.hashPair(left, right);
                nextLevel.push(combinedHash);
            }
            this.levels.push(nextLevel);
            currentLevel = nextLevel;
        }
    }

    // Hash a pair of data
    hashPair(left, right) {
        const sha256 = new SHA256();
        return sha256.hash(left + right); // Concatenate and hash
    }

    // Get the Merkle root
    getRoot() {
        return this.levels[this.levels.length - 1][0];
    }

    // Generate proof for a specific leaf
    getProof(leafIndex) {
        let index = leafIndex;
        const proof = [];

        for (let i = 0; i < this.levels.length - 1; i++) {
            const level = this.levels[i];
            const isRightNode = index % 2 === 1;
            const siblingIndex = isRightNode ? index - 1 : index + 1;

            if (siblingIndex < level.length) {
                proof.push({ 
                    hash: level[siblingIndex], 
                    position: isRightNode ? 'left' : 'right' 
                });
            }
            index = Math.floor(index / 2);
        }

        return proof;
    }

    // Verify the proof of a specific leaf
    static verifyProof(leafHash, proof, root) {
        let computedHash = leafHash;
        for (const { hash, position } of proof) {
            if (position === 'left') {
                computedHash = new SHA256().hash(hash + computedHash);
            } else {
                computedHash = new SHA256().hash(computedHash + hash);
            }
        }
        return computedHash === root;
    }
}

// Example usage
const data = [
    "data1", "data2", "data3", "data4", "data5",
    "data6", "data7", "data8", "data9", "data10", "data11"
];

// // Hash the data using the SHA256 class
// const sha256 = new SHA256();
// const hashedData = data.map(d => sha256.hash(d));

// // Create the Merkle Tree
// const merkleTree = new MerkleTree(hashedData);
// const root = merkleTree.getRoot();
// console.log("Merkle Root:", root);

// // Generate proof for a specific data (e.g., index 2)
// const proof = merkleTree.getProof(2);
// console.log("Proof for data3:", proof);

// // Verify the proof
// const isValid = MerkleTree.verifyProof(hashedData[2], proof, root);
// console.log("Is valid proof:", isValid);