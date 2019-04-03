package por

import(
    "bytes"
    "crypto/x509"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
    "fmt"
    "math/big"
)

type File_Info struct {
    // `json:"file_segment"`, `json:"sig"`, `json:"proof"`
	File_segment []byte 
	Signature []byte
	Merkle_proof []byte
}

type Ticket struct{
    // `json:"public_key"`, `json:"seed"`,`json:"proof_files"`
    // ecdsa.PublicKey 
	Public_key []byte
	Seed []byte
    Proof_files []File_Info 
}



// POR Related Capabilities
// This also functions as the scratch off ticket. The only difference between the one used for the 
// scratch off and the one used for communicating with a client is the client gets to pick tne files
// tested on in one scenario 

func calculateFileIndex(hash_string [32]byte, number_shards int64) int64{
    return big.NewInt(0).Mod(big.NewInt(0).SetBytes(hash_string[:]), big.NewInt(number_shards)).Int64()
}

func ProducePOR(minerKey *ecdsa.PrivateKey, blockchain_val []byte, stored_files *EncodedDataset, k uint) []byte {
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

    ticket := Ticket{Public_key: publicKeyAsBytes, Seed: seed, Proof_files: make([]File_Info,k)}

    s, r := big.NewInt(0), big.NewInt(0)
    sig_current := []byte(fmt.Sprintf("(%d,%d)", r, s))
    // TODO make faster by saving computation of repetitive strings given to sha 256
    
    var id_str []byte = append(blockchain_val, publicKeyAsBytes...)
    hash_str := append(id_str, seed...)
    strShaRes := sha256.Sum256(hash_str)
    current_file := calculateFileIndex(strShaRes, int64(len(stored_files.shards)))
    var i uint = 0
    for ;i < k; i++ {
        hash_str = append(id_str, sig_current...)
        hash_str = append(hash_str, stored_files.shards[current_file]...)
               
    	current_hash := sha256.Sum256(hash_str)
       
    	r, s, error = ecdsa.Sign(rand.Reader, minerKey, current_hash[:])
        if error != nil {
            panic(error)
        }
        
        sig_current = []byte(fmt.Sprintf("(%d,%d)", r, s))
    	add_fileinfo := File_Info{File_segment: stored_files.shards[current_file], Signature: sig_current, Merkle_proof: stored_files.hashes[current_file]}
    	ticket.Proof_files[i] = add_fileinfo
        // note this is problematic right now because it could select the same value twice
        hash_str = append(id_str, sig_current...)
        strShaRes = sha256.Sum256(hash_str)
        current_file = calculateFileIndex(strShaRes, int64(len(stored_files.shards)))
    }
    final_ticket, err := json.Marshal(ticket)
    if err != nil {
    	panic(err)
    }
    return final_ticket
}

func VerifyPOR(file_digests *EncodedDataset, blockchain_val []byte, ticket []byte, k uint) bool {
	// first, parse ticket 
    raw_ticket := json.RawMessage(ticket)
    
    var structured_ticket Ticket
    err := json.Unmarshal(raw_ticket, &structured_ticket)
    if err != nil {
    	panic(err)
    }
    // validate the ticket
    s, r := big.NewInt(0), big.NewInt(0)
    current_sig := []byte(fmt.Sprintf("(%d,%d)", r, s))
    written_key, error := x509.ParsePKIXPublicKey(structured_ticket.Public_key)
    if error != nil {
        panic(error)
    }
    // TODO: maybe change this but it should only ever be an ecdsa public key
    miners_key, correct_type := written_key.(*ecdsa.PublicKey)
    if !correct_type {
        fmt.Print("Type of miners key should only be ecdsa, fail")
        return false
    } 
    
    id_str := append(blockchain_val, structured_ticket.Public_key...)
    hash_str := append(id_str, structured_ticket.Seed...)
    shaRes := sha256.Sum256(hash_str)
    current_file := calculateFileIndex(shaRes, int64(len(file_digests.shards)))
    var i uint = 0
    for ; i < k; i++ {

        curr_file_info := structured_ticket.Proof_files[i]
        hash_str = append(id_str, current_sig...)
        hash_str = append(hash_str, file_digests.shards[i]...)
        
    	current_hash := sha256.Sum256(hash_str)
        
        if !bytes.Equal(curr_file_info.Merkle_proof, file_digests.hashes[current_file]) {
            return false
            //panic("File segment of Verifier does not match Prover's file")
        }
        var r, s *big.Int = big.NewInt(0), big.NewInt(0)
        sig_scan := bytes.NewReader(curr_file_info.Signature)
        _, err = fmt.Fscanf(sig_scan, "(%d,%d)", r, s)
        if err != nil {
            panic(err)
        }
        sig_check := ecdsa.Verify(miners_key, current_hash[:], r, s)
        
        if (!sig_check) {
            return false
            //panic("Failed signature check")
        }
        // note this is problematic right now because it could select the same value twice
        current_sig = curr_file_info.Signature
        hash_str = append(id_str, current_sig...)
        shaRes = sha256.Sum256(hash_str)
        current_file = calculateFileIndex(shaRes, int64(len(file_digests.shards)))
    }
	return true
}


//TODO: maybe switch to curve 25519 with a schnorr based sig scheme? -- do this later
func GenerateKey() *ecdsa.PrivateKey {
	priv_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return priv_key
}
