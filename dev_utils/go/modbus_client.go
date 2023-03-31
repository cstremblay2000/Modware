package dev_utils

import (
	"fmt"
	"log"

	"github.com/dpapathanasiou/go-modbus"
)

const (
	IX100_0 = 800
	IX100_1 = 801
	IX100_2 = 802
	IX100_3 = 803
	IX100_4 = 804
	IX100_5 = 805
	IX100_6 = 806
	IX100_7 = 807

	OPENPLC_ADDR = "127.0.0.1"
	OPENPLC_PORT = 5020
)

func main() {
	client, err := modbus.NewTCPClient(modbus.TCPClientConfig{Address: fmt.Sprintf("%s:%d", OPENPLC_ADDR, OPENPLC_PORT)})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	fmt.Printf("Connected to %v\n", client)

	err = client.WriteSingleCoil(1, IX100_0, true)
	if err != nil {
		log.Fatalf("Failed to write coil: %v", err)
	}

	coils, err := client.ReadCoils(1, IX100_0, 1)
	if err != nil {
		log.Fatalf("Failed to read coil: %v", err)
	}

	fmt.Printf("Coils: %v\n", coils)
}
