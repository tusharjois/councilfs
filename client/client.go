package client

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/tusharjois/councilfs/por"
	"time"
)

// MessageType identifies the type of the channel message. These types are
// inspired by the Lightning Network BOLT #2 at
// <https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md>
type MessageType int8

const (
	// ChannelOpen is sent when the channel is first created by the client. The
	// payload is the initial PaymentChannel.
	ChannelOpen MessageType = iota

	// ChannelAccepted is sent when the alderman accepts the creation of the
	// channel. The payload is the initial PaymentChannel with the ChannelOpen
	// message added.
	ChannelAccepted

	// FundsCreated is sent when the funding transaction backing this channel is
	// created by the client. The payload is the transaction ID of the funding
	// transaction.
	FundsCreated

	// FundsApproved is sent when the funding transaction backing this channel
	// is approved by the alderman. The payload is the transaction ID of the
	// funding transaction.
	FundsApproved

	// PORRequest is sent when a client wants to receive from a client a proof they are 
	// still holding the file they said they would be
    PORRequest

    // PORResponse is sent when an Alderman is trying to respond to a POR request 
    // made by a client. 
    PORResponse

	// SendPayment is sent when the client wants to send payment to the alderman
	// to save the file; this can be sent either after a valid POR is verified
	// or just on time. The payload is the payment being sent (little-endian)
	SendPayment

	// CloseChannel is sent by either the client or the server when the
	// PaymentChannel is to be closed. The client sends it when the POR fails to
	// verify or arbitrarily when the client no longer wants to maintain the
	// connection. The alderman sends it when the client does not send the
	// correct payment after the correct duration or arbitrarily if they no
	// longer wish to hold the file.
	CloseChannel
)

// PaymentChannel is a representation of the channel between a client and an
// alderman.
type PaymentChannel struct {
	ChannelID         []byte
	ClientPublicKey   []byte
	AldermanPublicKey []byte
	BlockchainState   []byte
	Payment           uint
	Interval          time.Duration
	Messages          []*ChannelMessage
	Encoding          *por.EncodedDataset
}

const CLIENTIDSIZE uint = 128

// ChannelMessage is a message between a client and an alderman. TODO: Add more description.
type ChannelMessage struct {
	mType           MessageType
	channelID       [CLIENTIDSIZE]byte
	signature       []byte
	senderPublicKey []byte
	payload         []byte
	prevHash        [sha256.Size]byte
}

// GetPayload returns the MessageType of the ChannelMessage and the associated payload.
func (msg *ChannelMessage) GetPayload() (MessageType, []byte, error) {
	// check the signature on the message 

	return msg.mType, msg.payload, nil // TODO: Verification
}

func (msg *ChannelMessage) GetSenderKey() []byte {
	return msg.senderPublicKey
}

func (pay *PaymentChannel) GetMostRecent() *ChannelMessage {
	return pay.Messages[len(pay.Messages) - 1]
}

func (pay *PaymentChannel) GetID() []byte {
	return pay.ChannelID[:]
}

func (msg *ChannelMessage) GetID() []byte{
	return msg.channelID[:];
}

func (pay *PaymentChannel) GetInterval() time.Duration {
	return pay.Interval
}

// update your own message channel with a pointer to a message you hold
func (pay *PaymentChannel) UpdateMessages(msg *ChannelMessage) {
	pay.Messages = append(pay.Messages, msg)
}

func (pay *PaymentChannel) DebugPrint() {
	for i := 0; i < len(pay.Messages); i++ {
		fmt.Printf("%v\n", pay.Messages[i])
	}
}

// NewMessage creates a ChannelMessage with specified parameters. TODO: Add more description.
func NewMessage(mType MessageType, v interface{},channelID []byte, signingKey *ecdsa.PrivateKey, prev *ChannelMessage) *ChannelMessage {
	jsonPayload, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	toSign := make([]byte, len(jsonPayload))
	copy(toSign, jsonPayload)
	var prevHash [sha256.Size]byte
	if prev != nil {
		jsonPrev, err := json.Marshal(prev)
		if err != nil {
			panic(err)
		}
		prevHash = sha256.Sum256(jsonPrev)
	}
	toSign = append(toSign, prevHash[:]...)
	toSignHash := sha256.Sum256(toSign)

	r, s, err := ecdsa.Sign(rand.Reader, signingKey, toSignHash[:])
	if err != nil {
		panic(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		panic(err)
	}

	newMessage := &ChannelMessage{
		mType:           mType,
		channelID:       [CLIENTIDSIZE]byte{},
		signature:       []byte(fmt.Sprintf("(%d,%d)", r, s)),
		senderPublicKey: publicKeyBytes,
		payload:         jsonPayload,
		prevHash:        prevHash,
	}
    
    if len(channelID) < 0 {
    	panic("Attempted overflow???")
    }
    if uint(len(channelID)) != CLIENTIDSIZE {
    	panic("Channel ID is of incorrect size")
    }
	copy(newMessage.channelID[:],channelID)

	return newMessage
}

// OpenChannel creates a new PaymentChannel between a client and an alderman.
func OpenChannel(clientKey *ecdsa.PrivateKey, aldermanKey *ecdsa.PublicKey, payment uint,
	paymentInterval time.Duration, encoding *por.EncodedDataset) (*PaymentChannel, ChannelMessage, por.EncodedDataset) {
	newChannel := new(PaymentChannel)
	newChannel.ChannelID = make([]byte, 128)
	_, err := rand.Read(newChannel.ChannelID)
	if err != nil {
		panic(err)
	}

	clientKeyBytes, err := x509.MarshalPKIXPublicKey(&clientKey.PublicKey)
	if err != nil {
		panic(err)
	}
	newChannel.ClientPublicKey = clientKeyBytes
    
	aldermanKeyBytes, err := x509.MarshalPKIXPublicKey(aldermanKey)
	if err != nil {
		panic(err)
	}
	newChannel.AldermanPublicKey = aldermanKeyBytes

	newChannel.Payment = payment
	newChannel.Interval = paymentInterval

	// Note that this can become nil after the file is uploaded
	// can't do this in a regular networking setting
	newChannel.Encoding = encoding
	newChannel.BlockchainState = make([]byte, 6)
	newMessage := NewMessage(ChannelOpen, newChannel, newChannel.ChannelID, clientKey, nil)

	newChannel.Messages = make([]*ChannelMessage, 0)
	newChannel.UpdateMessages(newMessage)

	return newChannel, *newMessage, *encoding
}

// VerifyPOR checks that an alderman is actually holding the file they clain to be 
// [the POR is correctly computed]
func (pay *PaymentChannel) VerifyPOR(clientKey *ecdsa.PrivateKey, k uint) ChannelMessage {
	_,clientMsg, err := pay.Messages[len(pay.Messages)-1].GetPayload()
	
	if err != nil {
		panic(err)
	}
	
	if pay.Encoding != nil {
		rawmsg := json.RawMessage(clientMsg)
		var valuebytes []byte
		err = json.Unmarshal(rawmsg, &valuebytes)
		if err != nil {
			panic(err)
		}
		if !por.VerifyPOR(pay.Encoding, pay.BlockchainState, valuebytes, k) {
			print("Message failed to verify")
			closeMessage := NewMessage(CloseChannel, make([]byte, 0), pay.ChannelID, clientKey, pay.Messages[len(pay.Messages)-1])
			pay.UpdateMessages(closeMessage)
			return *closeMessage
		}
	}

	payMessage := NewMessage(SendPayment, pay.Payment, pay.ChannelID, clientKey, pay.Messages[len(pay.Messages)-1])
	pay.UpdateMessages(payMessage)
	return *payMessage
}

// RequestPOR done by client 
func (pay *PaymentChannel) RequestPOR(clientKey *ecdsa.PrivateKey, k uint) ChannelMessage {
	// because the client is requesting the POR, they choose the challenge and there is no
	// puzzle value
	// provide list of indices to test on 
	var identifierstring []byte = make([]byte, 10)
	_, err := rand.Read(identifierstring)
	if err != nil {
		panic(err)
	}
	
	challenge := NewMessage(PORRequest, identifierstring, pay.ChannelID, clientKey, pay.Messages[len(pay.Messages)-1])
    pay.UpdateMessages(challenge)
	return *challenge
}

func (pay *PaymentChannel) RespondToPOR(aldermanKey *ecdsa.PrivateKey, k uint) ChannelMessage {
	lastMessage := pay.Messages[len(pay.Messages)-1]
    
	if msgType, payload, _ := lastMessage.GetPayload(); msgType == PORRequest {
        // use the payload as the challenge for the POR
        // TODO ask TUshar if we want go tie the blockchainVal to the payment 
        // channel... 
        proofToSend := por.ProducePOR(aldermanKey, pay.BlockchainState, pay.Encoding, k, payload)
        message := NewMessage(PORResponse, &proofToSend, pay.ChannelID, aldermanKey, lastMessage)
        pay.UpdateMessages(message)
	    return *message
	} else {
		// code was called with the wrong input
		panic("Received bad input -- message was not for a POR")
	}
}