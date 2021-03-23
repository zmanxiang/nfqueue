package main

import (
	"context"
	"fmt"
	"github.com/florianl/go-nfqueue"
	"golang.org/x/net/icmp"
	"time"
)

const (
	ProtocolICMP = 1
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
		msg, err := icmp.ParseMessage(ProtocolICMP, *a.Payload)
		if err != nil {
			fmt.Println(err)
			fmt.Printf("nfqueue payload: %s \n", convertPacketToString(*a.Payload))
		} else {
			fmt.Printf("%+v \n", *msg)
			if body, err := msg.Body.(*icmp.Echo); err {
				// Now we can access Body.Data
				fmt.Println("data string")
				fmt.Println(string(body.Data))
			}
			fmt.Printf("body: %s", msg.Body)
		}

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
	return fmt.Sprintf("%x", data)
}
