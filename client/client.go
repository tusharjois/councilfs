package client

import (
	"crypto/rand"
	"github.com/tusharjois/councilfs/por"
	"time"
)

// ChannelState
type MessageType int8

const (
	// ChannelOpen is set when the channel is first created by the client.
	ChannelOpen MessageType = iota

	// ChannelAccepted is set when the alderman accepts the creation of the
	// channel.
	ChannelAccepted
)

// PaymentChannel is a representation of the channel between a client and an
// alderman.
type PaymentChannel struct {
	channelID         []byte
	clientPublicKey   []byte
	aldermanPublicKey []byte
	payment           uint
	interval          time.Duration
	Encoding          *por.EncodedDataset
}

// OpenChannel creates a new PaymentChannel between a client and an alderman.
func OpenChannel(clientKey []byte, aldermanKey []byte, payment uint,
	paymentInterval time.Duration, encoding *por.EncodedDataset) *PaymentChannel {

	newChannel := new(PaymentChannel)
	newChannel.channelID = make([]byte, 128)
	_, err := rand.Read(newChannel.channelID)
	if err != nil {
		panic(err)
	}
	newChannel.clientPublicKey = clientKey
	newChannel.aldermanPublicKey = aldermanKey
	newChannel.payment = payment
	newChannel.interval = paymentInterval

	// Note that this can become nil after the file is uploaded
	newChannel.Encoding = encoding

	return newChannel
}

// Engage
func (*PaymentChannel) Engage(proof []byte) bool {
	return false
}
