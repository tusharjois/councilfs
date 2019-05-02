package alderman

import (
    "testing"
    "github.com/tusharjois/councilfs/client"
    "github.com/tusharjois/councilfs/por"
)

func NetworkFunctionality(pay *client.PaymentChannel, addMsg client.ChannelMessage) {
    giveToClient := new(client.ChannelMessage)
    *giveToClient = addMsg
    // maybe this will work I don't know 
    pay.UpdateMessages(giveToClient)
}

func TestClientAldermanInteraction(test *testing.T) {
    const k uint = 2
	// first, generate a file to use and encode
    bramStoker := []byte("Left Munich at 8:35 P. M., on 1st May, arriving at Vienna early next morning; should have arrived at 6:46, but train was an hour late. Buda-Pesth seems a wonderful place, from the glimpse which I got of it from the train and the little I could walk through the streets. I feared to go very far from the station, as we had arrived late and would start as near the correct time as possible. The impression I had was that we were leaving the West and entering the East; the most western of splendid bridges over the Danube, which is here of noble width and depth, took us among the traditions of Turkish rule.")
    encodedFile, err := por.CreateErasureCoding(bramStoker, 2, 7)
    if err != nil {
        panic(err)
    }

    aldermanPiece, error := por.SelectSegments(encodedFile, []int{2, 4, 5,6})
    if error != nil {
        panic(error)
    }
    clientKey := por.GenerateKey()
    aldermanKey := por.GenerateKey()
    aldermanPublic := aldermanKey.PublicKey
    /*
    //clientPublic := clientKey.Public()
    ecdsaPubKey, correctType := aldermanPublic.(ecdsa.PublicKey)
    fmt.Print(ecdsaPubKey)
    if !correctType {
        fmt.Print("Type of miners key should only be ecdsa, fail")
        panic("Wrong key type")
    }
    */
	clientchannel, firstCMsg, encoding := client.OpenChannel(clientKey, &aldermanPublic, 20, 10, aldermanPiece)

    alderchannel, firstAMsg := AcceptChannel(aldermanKey, firstCMsg)

    alderchannel.Encoding = &encoding
    // do a simple walkthrough of the protocol 
    // have client send a POR request
    NetworkFunctionality(clientchannel, firstAMsg)

    secondCMsg := clientchannel.RequestPOR(clientKey, k)
    NetworkFunctionality(alderchannel, secondCMsg)

    secondAMsg := alderchannel.RespondToPOR(aldermanKey, k)
    NetworkFunctionality(clientchannel, secondAMsg)
    thirdCMsg := clientchannel.VerifyPOR(clientKey, k)
    NetworkFunctionality(alderchannel, thirdCMsg)

    // make sure the communication channels have correct values
    alderchannel.DebugPrint()
    clientchannel.DebugPrint()
    return
}