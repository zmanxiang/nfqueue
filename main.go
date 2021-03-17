package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/florianl/go-nfqueue"
	"time"
)

func main() {
	for {
		nfqueueListener()
		fmt.Println("===== waiting for 10 seconds =====")
		time.Sleep(10 * time.Second)
	}
}

func nfqueueListener() {
	config := nfqueue.Config{
		NfQueue:      100,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		fmt.Printf("nfqueue payload: %v \n", convertPacketToString(*a.Payload))
		fmt.Printf("hwAddress: %x \n", convertPacketToString(*a.HwAddr))
		fmt.Printf("hwProtocoal: %+v \n", *a.HwProtocol)
		nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.Register(ctx, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}

func convertPacketToString(data []byte) string {
	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		return "error message"
	}
	return string(decoded);
}