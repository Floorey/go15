package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketStats struct {
	ProtocolCount map[gopacket.LayerType]int
	TotalPackets  int
	TotalBytes    int
	AvgPacketSize float64
}

func main() {
	done := make(chan struct{})

	fmt.Println("Choose an option:")
	fmt.Println("1. Track packets with metadata")
	fmt.Println("2. Track packets with detailed info")
	fmt.Println("3. Track packets with statistics")
	fmt.Println("4. Exit")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		choice := scanner.Text()

		switch choice {
		case "1":
			trackPackets(true)
		case "2":
			trackPackets(false)
		case "3":
			go trackPacketStats(done)
			select {
			case <-done:
				fmt.Println("Packet tracking completed.")
			case <-time.After(5 * time.Second):
				fmt.Println("Timeout: Packet tracking aborted.")
			}
		case "4":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid option. Please choose again:")
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func trackPacketStats(done chan struct{}) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for i, device := range devices {
		fmt.Printf("%d. %s (%s)\n", i+1, device.Name, device.Description)
	}

	fmt.Println("Choose a network interface:")
	var ifaceIndex int
	if _, err := fmt.Scanln(&ifaceIndex); err != nil {
		log.Fatal(err)
	}

	if ifaceIndex < 1 || ifaceIndex > len(devices) {
		fmt.Println("Invalid interface index.")
		return
	}
	iface := devices[ifaceIndex-1].Name

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var stats PacketStats
	stats.ProtocolCount = make(map[gopacket.LayerType]int)

	packetChan := packetSource.Packets()

	for packet := range packetChan {
		trackPacketStatsHelper(packet, &stats)
	}

	// Benachrichtige, dass die Go-Routine abgeschlossen ist
	close(done)
}

func trackPacketStatsHelper(packet gopacket.Packet, stats *PacketStats) {
	stats.TotalPackets++
	stats.TotalBytes += len(packet.Data())

	for _, layer := range packet.Layers() {
		stats.ProtocolCount[layer.LayerType()]++
	}
	stats.AvgPacketSize = float64(stats.TotalBytes) / float64(stats.TotalPackets)
}

func trackPackets(withMetadata bool) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for i, device := range devices {
		fmt.Printf("%d. %s (%s)\n", i+1, device.Name, device.Description)
	}

	fmt.Println("Choose a network interface:")
	var ifaceIndex int
	if _, err := fmt.Scanln(&ifaceIndex); err != nil {
		log.Fatal(err)
	}

	if ifaceIndex < 1 || ifaceIndex > len(devices) {
		fmt.Println("Invalid interface index.")
		return
	}
	iface := devices[ifaceIndex-1].Name

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var stats PacketStats
	stats.ProtocolCount = make(map[gopacket.LayerType]int)

	packetChan := packetSource.Packets()

	for packet := range packetChan {
		if withMetadata {
			printPacketInfo(packet, true)
		} else {
			printPacketInfo(packet, false)
		}
		trackPacketStatsHelper(packet, &stats)
	}
	printPacketStats(stats)
}

func printPacketInfo(packet gopacket.Packet, withMetadata bool) {
	if withMetadata {
		metadata := packet.Metadata()
		fmt.Println("Timestamp:", metadata.Timestamp)
		fmt.Println("Capture Length:", metadata.CaptureInfo.CaptureLength)
		fmt.Println("Length:", metadata.Length)
	} else {
		fmt.Println(packet)
	}
}

func printPacketStats(stats PacketStats) {
	fmt.Println("Packet Statistics:")
	fmt.Println("Total Packets:", stats.TotalPackets)
	fmt.Println("Total Bytes:", stats.TotalBytes)
	fmt.Println("Average Packet Size:", stats.AvgPacketSize)

	fmt.Println("Protocol Counts:")
	for protocol, count := range stats.ProtocolCount {
		fmt.Printf("%s: %d\n", protocol, count)
	}
}
