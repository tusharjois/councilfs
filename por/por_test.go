package por

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestPOR(test *testing.T) {
	generatedMinerKey := GenerateKey()
	// make returns the slice NOT the underlying array
	var blockchainVal = make([]byte, 6)
	var testFileShard *EncodedDataset = new(EncodedDataset)
	testFileShard.shards = make([][]byte, 5)
	testFileShard.numDataShards = 5
	testFileShard.numParityShards = 0
	testFileShard.hashes = make([][]byte, 5)
	for i := 0; i < 5; i++ {
		testFileShard.shards[i] = make([]byte, 20)
		hash := sha256.Sum256(testFileShard.shards[i])
		testFileShard.hashes[i] = hash[:]
	}
	difficulty := big.NewInt(0)
	difficulty.Exp(big.NewInt(2), big.NewInt(250), nil) 
    proof := AttemptedMine(generatedMinerKey, blockchainVal, testFileShard, uint(5), difficulty)
	if !VerifyPOR(testFileShard, blockchainVal, proof, uint(5), difficulty) {
		test.Errorf("Correctly generated POR was not able to verify")
	}

	return
}
