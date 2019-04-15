package por

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
)

// Information needed for each file in the POR. FileSegment is the actual data of the 
// shard itself. Signature is a signature computed in the POR based off of the current
// puzzle value, public key, previous signature and current file while MerkleProof is a 
// proof that this file segment is actually tied to the original file segment stored by the
// client
type FileInfo struct {
	FileSegment []byte
	Signature   []byte
	MerkleProof []byte
}

// Ticket is the ticket that is actually produced by the POR done by a miner. It contains all information
// necessary to try and win the right to determine which files should next be included in a blockchain.
type Ticket struct {
	PublicKey  []byte
	Seed       []byte
	ProofFiles []FileInfo
}

func calculateFileIndex(hashString [32]byte, numberShards int64) int64 {
	return big.NewInt(0).Mod(big.NewInt(0).SetBytes(hashString[:]), big.NewInt(numberShards)).Int64()
}

func checkForWinningTicket(blockchainVal []byte, ticket []byte, difficultyParam *big.Int) bool{
	hashValue := sha256.Sum256(append(blockchainVal, ticket...))
    produceInteger := big.NewInt(0).SetBytes(hashValue[:])

    if produceInteger.Cmp(difficultyParam) == -1 {
        return true
    } else {
    	return false
    }
}

// Actual mining function. This function will attempt to find a ticket that when hashed with blockchainVal produces an integer value less than the difficulty
// parameter. When it finds such a value, it will return the ticket. blockchainVal is a byte string v || B_l || MR(x) || T where
// v = version number
// B_l = the previously mined block header
// MR(x) = hash of merkle root of transactions included in this block
// T = the current time
func AttemptedMine(minerKey *ecdsa.PrivateKey, blockchainVal []byte, storedFiles *EncodedDataset, numberSegments uint, difficultyParam *big.Int) []byte {
    for true {
        seed := make([]byte, 12)
    	_, err := rand.Read(seed)
    	if err != nil {
    		panic(err)
    	}

        potentialTicket := ProducePOR(minerKey, blockchainVal, storedFiles, numberSegments, seed)
        if checkForWinningTicket(blockchainVal, potentialTicket, difficultyParam) {
        	return potentialTicket
        }
    }

    return nil

}

func VerifyMine(fileDigests *EncodedDataset, blockchainVal []byte, ticket []byte, k uint, difficultyParam *big.Int) bool{
	porRes := VerifyPOR(fileDigests, blockchainVal, ticket, k)
	if porRes {
		return checkForWinningTicket(blockchainVal, ticket, difficultyParam)
	}
	return false
}

// Produces a Proof of Retrievability over segments of an encoded file F. The final returned value is a ticket that can be used
// by a miner if it fulfills the difficulty parameter. blockchainVal is equivalent to the blockchainVal described in AttemptedMine and
// seed is a random value that makes the ticket effectively random (so that any group of transactions with at least one seed could be used
// to produce a valid ticket)
func ProducePOR(minerKey *ecdsa.PrivateKey, blockchainVal []byte, storedFiles *EncodedDataset, k uint, seed []byte) []byte {
	publicKeyAsBytes, error := x509.MarshalPKIXPublicKey(&minerKey.PublicKey)
	if error != nil {
		panic(error)
	}

	ticket := Ticket{PublicKey: publicKeyAsBytes, Seed: seed, ProofFiles: make([]FileInfo, k)}

	s, r := big.NewInt(0), big.NewInt(0)
	sigCurrent := []byte(fmt.Sprintf("(%d,%d)", r, s))
	// TODO make faster by saving computation of repetitive strings given to sha 256

	var idStr []byte = append(blockchainVal, publicKeyAsBytes...)
	hashStr := append(idStr, seed...)
	strShaRes := sha256.Sum256(hashStr)
	currentFile := calculateFileIndex(strShaRes, int64(len(storedFiles.shards)))
	var i uint
	for ; i < k; i++ {
		hashStr = append(idStr, sigCurrent...)
		hashStr = append(hashStr, storedFiles.shards[currentFile]...)

		currentHash := sha256.Sum256(hashStr)

		r, s, error = ecdsa.Sign(rand.Reader, minerKey, currentHash[:])
		if error != nil {
			panic(error)
		}

		sigCurrent = []byte(fmt.Sprintf("(%d,%d)", r, s))
		addFileinfo := FileInfo{FileSegment: storedFiles.shards[currentFile], Signature: sigCurrent, MerkleProof: storedFiles.hashes[currentFile]}
		ticket.ProofFiles[i] = addFileinfo
		// note this is problematic right now because it could select the same value twice
		hashStr = append(idStr, sigCurrent...)
		strShaRes = sha256.Sum256(hashStr)
		currentFile = calculateFileIndex(strShaRes, int64(len(storedFiles.shards)))
	}
	finalTicket, err := json.Marshal(ticket)
	if err != nil {
		panic(err)
	}
	return finalTicket
}

// Takes in a ticket as a byte string and then parses it to produce a ticket object
func ParseTicket(ticket []byte) *Ticket {
	// first, parse ticket
	rawTicket := json.RawMessage(ticket)

	structuredTicket := new(Ticket)
    err := json.Unmarshal(rawTicket, &structuredTicket)
	if err != nil {
		panic(err)
	}
	return structuredTicket
}

// Verifies that a given POR ticket is correct in that the following must be true:
// 1) the POR was created with the correct blockchainVal [it matches the previous block in history]
// 2) the included files are segments of the fileDigests held by the verifier
// 3) the final value passes the publicly known difficulty parameter Z
func VerifyPOR(rootFileDigest [32]byte, blockchainVal []byte, ticket []byte, k uint) bool {
	structuredTicket := ParseTicket(ticket)
	// validate the ticket
	s, r := big.NewInt(0), big.NewInt(0)
	currentSig := []byte(fmt.Sprintf("(%d,%d)", r, s))
	writtenKey, error := x509.ParsePKIXPublicKey(structuredTicket.PublicKey)
	if error != nil {
		panic(error)
	}
	// TODO: maybe change this but it should only ever be an ecdsa public key
	minersKey, correctType := writtenKey.(*ecdsa.PublicKey)
	if !correctType {
		fmt.Print("Type of miners key should only be ecdsa, fail")
		return false
	}

	idStr := append(blockchainVal, structuredTicket.PublicKey...)
	hashStr := append(idStr, structuredTicket.Seed...)
	shaRes := sha256.Sum256(hashStr)
	currentFile := calculateFileIndex(shaRes, int64(len(fileDigests.shards)))
	var i uint
	for ; i < k; i++ {

		currFileInfo := structuredTicket.ProofFiles[i]
		hashStr = append(idStr, currentSig...)
		hashStr = append(hashStr, fileDigests.shards[i]...)

		currentHash := sha256.Sum256(hashStr)
        // the merkle proof right now is basically just a hash of the segment. 
        // so there are two ways to do this: have the verifier hold more information
        // or have the prover provide more information and the verifier do more computation
		if !bytes.Equal(currFileInfo.MerkleProof, fileDigests.hashes[currentFile]) {
			return false
			//panic("File segment of Verifier does not match Prover's file")
		}
		var r, s *big.Int = big.NewInt(0), big.NewInt(0)
		sigScan := bytes.NewReader(currFileInfo.Signature)
		_, err = fmt.Fscanf(sigScan, "(%d,%d)", r, s)
		if err != nil {
			panic(err)
		}
		sigCheck := ecdsa.Verify(minersKey, currentHash[:], r, s)

		if !sigCheck {
			return false
			//panic("Failed signature check")
		}
		// note this is problematic right now because it could select the same value twice
		currentSig = currFileInfo.Signature
		hashStr = append(idStr, currentSig...)
		shaRes = sha256.Sum256(hashStr)
		currentFile = calculateFileIndex(shaRes, int64(len(fileDigests.shards)))
	}

	// calculate final hash value
	return true
}

// Bare bones interface for producing an ecdsa asymmetric key. Accepts no arguments and pulls from cryptographic randomness 
func GenerateKey() *ecdsa.PrivateKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return privKey
}
