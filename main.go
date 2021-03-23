package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/oleiade/reflections.v1"
	"log"
	"math"
	"os"
	"strings"
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
		packet, err := parseTCPPacket(*a.Payload)
		if err != nil {
			fmt.Println(err)
			fmt.Printf("nfqueue payload: %s \n", convertPacketToString(*a.Payload))
		} else {
			fmt.Printf("%+v \n", packet)
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

var infolog = log.New(os.Stdout,
	"", 0)

type Packet struct {
	Gopacket gopacket.Packet
	IP *layers.IPv4
	TCP *layers.TCP
	Recompile func() ([]byte, error)
	Print func(...int)
}

func parseTCPPacket(packetData []byte) (packet Packet, err error) {

	packet.Gopacket = gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

	ipLayer := packet.Gopacket.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		err = errors.New("No IP layer!")
		infolog.Println(hex.Dump(packetData))
		return
	}
	packet.IP = ipLayer.(*layers.IPv4)
	ip := packet.IP

	tcpLayer := packet.Gopacket.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		err = errors.New("No TCP layer!")
		return
	}
	packet.TCP = tcpLayer.(*layers.TCP)
	tcp := packet.TCP

	packet.Recompile = func() ([]byte, error) {

		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths: true,
		}
		newBuffer := gopacket.NewSerializeBuffer()
		tcp.SetNetworkLayerForChecksum(ip)
		err := gopacket.SerializePacket(newBuffer, options, packet.Gopacket)
		if err != nil {
			return nil, err
		}
		return newBuffer.Bytes(), nil

	}


	toChar := func(b byte) rune {
		if b < 32 || b > 126 {
			return rune('.')
		}
		return rune(b)
	}
	toString := func(data []byte) string {
		var buffer bytes.Buffer
		for _, d := range data {
			buffer.WriteRune(toChar(d))
		}
		return buffer.String()
	}

	packet.Print = func(payloadLimits ...int) {

		result := fmt.Sprintf("Packet from %s:%d to %s:%d seq=%d ack=%d", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort, tcp.Seq, tcp.Ack)
		flags := strings.Split("FIN SYN RST PSH ACK URG ECE CWR NS", " ")
		for _, flag := range flags {
			val, err := reflections.GetField(tcp, flag)
			if err != nil {
				infolog.Println(err, "REFLECT ERROR!")
			}
			if val.(bool) {
				result += fmt.Sprintf(" %s", flag)
			}
		}
		infolog.Println(result)
		payloadLimit := 100
		if len(payloadLimits) > 0 {
			payloadLimit = payloadLimits[0]
		}
		if len(tcp.Payload) != 0 {
			infolog.Println("TCP PAYLOAD:", toString(tcp.Payload[:int(math.Min(float64(len(tcp.Payload)), float64(payloadLimit)))]))
		}
	}

	return

}
