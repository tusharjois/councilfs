package alderman

import (
	"crypto"
    "crypto/x509"
    "crypto/ecdsa"
	"github.com/tusharjois/councilfs/por"
    "github.com/tusharjois/councilfs/client"
    "encoding/json"
    "fmt"
    "time"
)

type Proof struct {
	challenge []byte
	proof []byte
}

// need data structure for alderman to keep track of demerits on exisitng alderman 
// create a hash table from public key of miners to a demertit counter
var OtherAlderman map[crypto.PublicKey]int = make(map[crypto.PublicKey]int)  

// Client Payment time counters
var ClientPayment map[string]int64 = make(map[string]int64)

// Can only be done by alderman to other alderman
// only occurs if a wrong proof was submitted 
// if the alderman refuses to respond, demerit and using BFT with other 
// alderman decide if they should be kicked out or not
// NOTE: this function does not protect against non availability 

func ProofofFailure(challenge []byte, proof_returned []byte, aldermanKey *ecdsa.PrivateKey) ([]byte, []byte) {
    punishmentProof := new(Proof)
    punishmentProof.challenge = challenge
    punishmentProof.proof = proof_returned

    proofOfFailure, err := json.Marshal(punishmentProof)
    if err != nil {
    	panic(err)
    }
    // sign this proof and attach to file
    // NOTE : this is bad because there is no check that this was actually the challenge the proof was computed on right now
    sig := por.SignAndMarshal(aldermanKey, proofOfFailure)
    return proofOfFailure, sig
}


// function stub to submit to blockchain
func submitProof(proof []byte, aldermanSignature []byte) {
    return
}

func getMinerKey(ticket []byte) ecdsa.PublicKey {
	ticketFromPOR := por.ParseTicket(ticket)
    key, err := x509.ParsePKIXPublicKey(ticketFromPOR.PublicKey)
    if err != nil {
    	panic(err)
    }
    identifierKey, correctType := key.(*ecdsa.PublicKey)
    if !correctType {
    	panic(correctType)
    }
	return *identifierKey
}

// Decide whether or not an alderman should be "voted off the island" and whether or not 
// a miner should be promoted to alderman
func checkForQuorum() {
	fmt.Println("Asked for a quorum check")
	return
}


// verify that a miner is storing the file F correctly. It is meant to be called
// after the alderman/miner has issued genChallenge to another miner and recieved back a ticket
func VerifyMiner(k uint, genChallenge []byte, ticket []byte, fileCheck *por.EncodedDataset, isAlderman bool, 
	aldermanKey *ecdsa.PrivateKey, minerKey crypto.PublicKey) bool{

    if por.VerifyPOR(fileCheck, genChallenge, ticket, k) {
    	if getMinerKey(ticket) != minerKey {
    		panic("Miner key for communication and miner key in ticket do not match")
    	}
    	return true
    } else {
    	if isAlderman {
    		proof, alderSig := ProofofFailure(genChallenge, ticket, aldermanKey)
    		submitProof(proof, alderSig)
    		keyFromTicket := getMinerKey(ticket)
    		_, keyExists := OtherAlderman[keyFromTicket]
    		if keyExists {
                OtherAlderman[keyFromTicket] = OtherAlderman[keyFromTicket] + 1
    		} else {
                OtherAlderman[keyFromTicket] = 1
    		}
    		// need to decide when the "acceptable amounts of demerits" pass a threshold in which the miners should vote in
    		// I can easily see how you would do this if you had smart contract 
    		if OtherAlderman[keyFromTicket] >= 3 {
    			checkForQuorum();
    		}
    	}
    	return false
    }
}

func AcceptChannel(aldermanKey *ecdsa.PrivateKey, clientMsg client.ChannelMessage) (*client.PaymentChannel, client.ChannelMessage) {
     clientChannel := new(client.PaymentChannel)
     _, payload, err := clientMsg.GetPayload()
     if err != nil {
        panic(err)
     }
     msg := json.RawMessage(payload)

     err = json.Unmarshal(msg, &clientChannel)
     if err != nil {
     	panic(err)
     }
     // store this somewhere please 
     channelPaymentID := append(clientMsg.GetSenderKey(), clientMsg.GetID()...)
     
     //channelPaymentID := append(clientMsg.GetSenderKey(), clientChannel.GetID()...)
     _, ok := ClientPayment[string(channelPaymentID)];
     if ok {
     	// the channel already exists -- don't respond to the client but add it to messages?
     	panic("Channel already exists")
     } 
     
     addMsg := new(client.ChannelMessage)
     *addMsg = clientMsg
     clientChannel.UpdateMessages(addMsg)
     sendNewMsg := client.NewMessage(client.ChannelAccepted, clientChannel, addMsg.GetID(), aldermanKey, addMsg)
     clientChannel.UpdateMessages(sendNewMsg)

     return clientChannel, *sendNewMsg
}

// function runs on channel and checks for a funds transfer
// isn't this tied to a blockchain? what do you need to do specifically
// for 
func CheckPayment(channel *client.PaymentChannel, minerKey *ecdsa.PrivateKey, timeCurrent int64) *client.ChannelMessage {
	// TODO do check to see if a client has paid yet 
    mostRecentMsg := channel.GetMostRecent()
	// if channelID dictionary is empty or nil then a client has no
	// outstanding payment due, otherwise 
	channelPaymentID := append(mostRecentMsg.GetSenderKey(), channel.GetID()...)
    if startTime, ok := ClientPayment[string(channelPaymentID)]; ok {
    	unixCurrentTime := time.Unix(timeCurrent, int64(0))
    	if unixCurrentTime.Sub(time.Unix(startTime, int64(0))) > channel.GetInterval() {
    		// close payment channel
            closeMessage := client.NewMessage(client.CloseChannel, make([]byte, 0), channel.GetID(),
        		minerKey, mostRecentMsg)
            //channel.UpdateMessages(closeMessage)
        	return closeMessage
    	}
    }
    // in a main loop for the payment channel, reset ClientPayment whenever a payment
    // is received and have the alderman iterate through the ClientPayment dictionary checking for payment 
    // and closing out channels appropriately
    return nil 
}

// DownloadFile is called when a client requests from an alderman a EncodedDataset
// it is assumed that there is a transaction on the blockchain containing the most 
// recent digest of the file's root, signed by the client, and stored by all the alderman
func DownloadFile(pay *client.PaymentChannel) *por.EncodedDataset {
    return pay.Encoding
}

