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

type FileInfo struct {
	// `json:"fileSegment"`, `json:"sig"`, `json:"proof"`
	FileSegment []byte
	Signature   []byte
	MerkleProof []byte
}

type Ticket struct {
	// `json:"publicKey"`, `json:"seed"`,`json:"proofFiles"`
	// ecdsa.PublicKey
	PublicKey  []byte
	Seed       []byte
	ProofFiles []FileInfo
}

// POR Related Capabilities
// This also functions as the scratch off ticket. The only difference between the one used for the
// scratch off and the one used for communicating with a client is the client gets to pick tne files
// tested on in one scenario

func calculateFileIndex(hashString [32]byte, numberShards int64) int64 {
	return big.NewInt(0).Mod(big.NewInt(0).SetBytes(hashString[:]), big.NewInt(numberShards)).Int64()
}

func ProducePOR(minerKey *ecdsa.PrivateKey, blockchainVal []byte, storedFiles *EncodedDataset, k uint) []byte {
	// use random seed to select portions of file to compute the POR over
	seed := make([]byte, 6)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}
	// mother F WHY JUST FRICKIN WHY
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

func VerifyPOR(fileDigests *EncodedDataset, blockchainVal []byte, ticket []byte, k uint) bool {
	// first, parse ticket
	rawTicket := json.RawMessage(ticket)

	var structuredTicket Ticket
	err := json.Unmarshal(rawTicket, &structuredTicket)
	if err != nil {
		panic(err)
	}
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
	return true
}

//TODO: maybe switch to curve 25519 with a schnorr based sig scheme? -- do this later
func GenerateKey() *ecdsa.PrivateKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return privKey
}
