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
	channelID         []byte
	clientPublicKey   []byte
	aldermanPublicKey []byte
	blockchainState   []byte
	payment           uint
	interval          time.Duration
	messages          []*ChannelMessage
	Encoding          *por.EncodedDataset
}

// ChannelMessage is a message between a client and an alderman. TODO: Add more description.
type ChannelMessage struct {
	mType           MessageType
	channelID       []byte
	signature       []byte
	senderPublicKey []byte
	payload         []byte
	prevHash        [sha256.Size]byte
}

// GetPayload returns the MessageType of the ChannelMessage and the associated payload.
func (msg *ChannelMessage) GetPayload() (MessageType, []byte, error) {
	return msg.mType, msg.payload, nil // TODO: Verification
}

// NewMessage creates a ChannelMessage with specified parameters. TODO: Add more description.
func NewMessage(mType MessageType, v interface{}, channelID []byte, signingKey *ecdsa.PrivateKey, prev *ChannelMessage) *ChannelMessage {
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
		channelID:       channelID,
		signature:       []byte(fmt.Sprintf("(%d,%d)", r, s)),
		senderPublicKey: publicKeyBytes,
		payload:         jsonPayload,
		prevHash:        prevHash,
	}

	copy(newMessage.channelID, channelID)

	return newMessage
}

// OpenChannel creates a new PaymentChannel between a client and an alderman.
func OpenChannel(clientKey *ecdsa.PrivateKey, aldermanKey *ecdsa.PublicKey, payment uint,
	paymentInterval time.Duration, encoding *por.EncodedDataset) (*PaymentChannel, *ChannelMessage) {

	newChannel := new(PaymentChannel)
	newChannel.channelID = make([]byte, 128)
	_, err := rand.Read(newChannel.channelID)
	if err != nil {
		panic(err)
	}

	clientKeyBytes, err := x509.MarshalPKIXPublicKey(&clientKey.PublicKey)
	if err != nil {
		panic(err)
	}
	newChannel.clientPublicKey = clientKeyBytes

	aldermanKeyBytes, err := x509.MarshalPKIXPublicKey(aldermanKey)
	if err != nil {
		panic(err)
	}
	newChannel.aldermanPublicKey = aldermanKeyBytes

	newChannel.payment = payment
	newChannel.interval = paymentInterval

	// Note that this can become nil after the file is uploaded
	newChannel.Encoding = encoding
	newChannel.blockchainState = make([]byte, 6)
	newMessage := NewMessage(ChannelOpen, newChannel, newChannel.channelID, clientKey, nil)

	newChannel.messages = make([]*ChannelMessage, 0)
	newChannel.messages = append(newChannel.messages, newMessage)

	return newChannel, newMessage
}

// Engage allows the client to participate in the PaymentChannel.
func (pay *PaymentChannel) Engage(proof []byte, clientKey *ecdsa.PrivateKey) *ChannelMessage {
	if pay.Encoding != nil {
		if !por.VerifyPOR(pay.Encoding, pay.blockchainState, proof, pay.Encoding.Length()) {
			closeMessage := NewMessage(CloseChannel, make([]byte, 0), pay.channelID, clientKey, pay.messages[len(pay.messages)-1])
			pay.messages = append(pay.messages, closeMessage)
			return closeMessage
		}
	}

	payMessage := NewMessage(SendPayment, pay.payment, pay.channelID, clientKey, pay.messages[len(pay.messages)-1])
	pay.messages = append(pay.messages, payMessage)
	return payMessage
}
