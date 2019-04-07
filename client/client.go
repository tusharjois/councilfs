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
	payment           uint
	interval          time.Duration
	messages          []ChannelMessage
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
func (ChannelMessage) GetPayload() (MessageType, []byte, error) {
	return ChannelOpen, nil, nil // TODO
}

// OpenChannel creates a new PaymentChannel between a client and an alderman.
func OpenChannel(clientKey *ecdsa.PrivateKey, aldermanKey *ecdsa.PublicKey, payment uint,
	paymentInterval time.Duration, encoding *por.EncodedDataset) *PaymentChannel {

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

	jsonPayload, err := json.Marshal(newChannel)
	toSign := make([]byte, len(jsonPayload))
	copy(toSign, jsonPayload)
	var emptyHash [sha256.Size]byte
	toSign = append(toSign, emptyHash[:]...)
	toSignHash := sha256.Sum256(toSign)

	r, s, err := ecdsa.Sign(rand.Reader, clientKey, toSignHash[:])
	if err != nil {
		panic(err)
	}

	newMessage := ChannelMessage{
		mType:           ChannelOpen,
		channelID:       make([]byte, len(newChannel.channelID)),
		signature:       []byte(fmt.Sprintf("(%d,%d)", r, s)),
		senderPublicKey: clientKeyBytes,
		payload:         jsonPayload,
		prevHash:        emptyHash,
	}

	copy(newMessage.channelID, newChannel.channelID)

	return newChannel
}

// Engage
func (*PaymentChannel) Engage(proof []byte) bool {
	return false
}
