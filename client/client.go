package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	util "rsa-util"
	"strconv"
	"strings"
	"time"
)

var serverKey []big.Int
var E, D, N big.Int

func main() {

	logger := log.Default()

	// Generate our own key pair.
	E, D, N = util.GenerateKeyPair(2048, logger)

	logger.Println("Generated our key pair (E, D, N)")

	// Establishing Connection
	connection, err := net.Dial("unix", "/tmp/irc.sock")
	if err != nil {
		logger.Fatalf("error connection to server at /tmp/irc.sock: %s\n", err)
	}

	defer connection.Close()

	// Receiving the server's key pair
	if received, ok := util.ReceiveKeyPair(&connection); !ok {
		os.Exit(1)
	} else {
		serverKey = received
	}

	logger.Println("Received server's public key [E, N]")

	// Sending our key pair.
	if !util.SendKeyPair(&connection, []big.Int{E, N}) {
		os.Exit(1)
	}

	// Identify yourself by sending your pid.
	pidStr := strconv.Itoa(os.Getpid())
	if len(pidStr) > 5 {
		pidStr = pidStr[len(pidStr)-5:]
	} else if len(pidStr) < 5 {
		pidStr += strings.Repeat("0", 5-len(pidStr))
	}

	pidStr = util.Encrypt(util.Encode(pidStr), serverKey[0], serverKey[1])[0]

	if _, err := connection.Write([]byte(pidStr)); err != nil {
		logger.Fatalf("error identifying ourselves to the server: %s\n", err)
	}

	// Connect to the other socket.
	interclientConnection, err := net.Dial("unix", "/tmp/inter-client.sock")
	if err != nil {
		logger.Fatalf("error connection to server at /tmp/inter-client.sock: %s\n", err)
	}

	// This function only receives messages from the server sent by other clients,
	// on a dedicated socket. It's started concurrently using go routines.
	go func() {

		buffer := make([]byte, 10240)
		ack := "1"

		for {
			encryptedMessage := []string{}

			for {
				n, err := interclientConnection.Read(buffer)
				if err != nil {
					if errors.Is(err, io.EOF) {
						return
					} else {
						logger.Printf("error reading from server: %s", err.Error())
					}
				}

				if string(buffer[:n]) == "-1" {
					break
				} else {
					encryptedMessage = append(encryptedMessage, string(buffer[:n]))
				}

				n, err = interclientConnection.Write([]byte(ack))
				if (err != nil) || n != len(ack) {
					logger.Printf("error sending ack\n")
				}
			}

			message := util.Decode(util.Decrypt(encryptedMessage, D, N))

			fmt.Printf("\r[%s] %s%s%s%s\n", time.Now().Format(time.TimeOnly), "(client", message[:5], ") ", message[5:])
			fmt.Printf("\rYou: ")
		}
	}()

	// Starting the loop that reads from stdin a line, then sends it to the server.
	scanner := bufio.NewScanner(os.Stdin)
	for {

		fmt.Printf("You: ")
		scanner.Scan()

		line := scanner.Text()

		if len(line) == 0 {
			logger.Println("Closing the connection.")
			break
		}

		// encoding/decoding. This returns a list of encoded groups of five characters.
		encryptedMessage := util.Encrypt(util.Encode(line), serverKey[0], serverKey[1])
		ack := make([]byte, 1024)

		for _, encryptedChunk := range encryptedMessage {

			// Write the 5-character group.
			n, err := connection.Write([]byte(encryptedChunk))

			if err != nil {
				logger.Fatalf("error writing to connection: %s\n", err)
			} else if n != len(encryptedChunk) {
				logger.Printf("error: partial write\n")
				continue
			}

			// Receive an acknowledgment.
			n, err = connection.Read(ack)

			if err != nil || strings.Compare(string(ack[:n]), "1") != 0 {
				logger.Printf("error receiving ack\n")
			}
		}

		_, err := connection.Write([]byte("-1"))
		if err != nil {
			logger.Fatalf("error writing to connection: %s\n", err)
		}
	}

	if err := connection.Close(); err != nil {
		logger.Fatalf("error closing connection: %s\n", err)
	}
}
