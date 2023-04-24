package main

import (
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	util "rsa-util"
	"strings"
	"syscall"
)

type Client struct {
	Connection            *net.Conn
	InterClientConnection *net.Conn
	N                     big.Int
	E                     big.Int
}

// Create a map of connections
var connectedClients = map[string]Client{}
var E, D, N big.Int
var interClientServer net.Listener

func main() {

	// Creating a logger
	logger := log.Default()

	// Establishing a signal handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Generating a key pair
	E, D, N = util.GenerateKeyPair(2048, logger)

	logger.Println("Generated our key pair (E, D, N)")

	// I will use d for decryption, e for encryption.
	// I will make e public, d private.
	// Clients will use e to encrypt messages directed at me.

	server, err := net.Listen("unix", "/tmp/irc.sock")
	if err != nil {
		logger.Fatalf("error creating socket: %s\n", err.Error())
	}

	interClientServer, err = net.Listen("unix", "/tmp/inter-client.sock")
	if err != nil {
		logger.Fatalf("error creating socket: %s\n", err.Error())
	}

	defer server.Close()
	defer interClientServer.Close()

	logger.Println("Starting to listen on /tmp/irc.sock")

	for {

		select {

		// If we received a terminating signal.
		case <-sigs:

			if err := server.Close(); err != nil {
				log.Fatalf("error closing the server: %s", err)
			}

			if err := interClientServer.Close(); err != nil {
				log.Fatalf("error closing the server: %s", err)
			}

			log.Println("Closed server. Shutting down.")
			os.Exit(0)

		// If we we received another connection.
		case connection := <-acceptConnection(server, logger):

			pidStr := initializeClient(&connection, *logger)
			go processClient(pidStr, logger)

		}
	}
}

// This function performs key and identity exchange.
func initializeClient(connection *net.Conn, logger log.Logger) string {

	// Sending our own key pair.
	if !util.SendKeyPair(connection, []big.Int{E, N}) {
		return ""
	}

	var client Client

	// Receiving the client's key pair.
	if received, ok := util.ReceiveKeyPair(connection); !ok {
		return ""
	} else {
		client = Client{
			Connection: connection,
			E:          received[0],
			N:          received[1],
		}
	}

	// Receiving the client's pid.
	pid := make([]byte, 1024)
	var pidStr string

	if n, err := (*connection).Read(pid); err != nil {
		logger.Printf("error reading client's pid: %s\n", err)
		(*connection).Close()
	} else {

		pidStr = util.Decode(util.Decrypt([]string{string(pid[:n])}, D, N))

		connectedClients[pidStr] = client
	}

	logger.Printf("A new client with process id: %s has connected\n", pidStr)
	logger.Printf("Received client %s's key pair [E, N]\n", pidStr)

	return pidStr
}

// This function accepts a client's connection on the main socket.
// It returns a channel on which we select/block with another channel that receives the terminatign signals.
func acceptConnection(server net.Listener, logger *log.Logger) <-chan net.Conn {

	conn := make(chan net.Conn, 1)

	go func() {
		c, err := server.Accept()

		if err != nil {
			// If it's due to a closed connection, do not through an error message, and return.
			if errors.Is(err, net.ErrClosed) {
				return
			} else {
				logger.Printf("error accepting connection: %s\n", err.Error())
			}
		} else {
			conn <- c
		}
	}()

	return conn
}

// This function is the main function handling a connected client.
// It reads, and forwards what a client sends.
func processClient(connectionId string, logger *log.Logger) {

	buffer := make([]byte, 10240)
	connection := connectedClients[connectionId].Connection
	encodedPidStr := util.Encode(connectionId)

	// Accepting the client's connection to the other socket.
	ic, err := interClientServer.Accept()
	if err != nil {
		logger.Printf("failed to accept client's connection to the inter-client socket: %s\n", err)
		return
	}

	// Setting the interclient connection in the client struct.
	if c, ok := connectedClients[connectionId]; ok {
		c.InterClientConnection = &ic
		connectedClients[connectionId] = c
	}

	ack := "1"
	// Looping over received full message
	for {
		ackBuffer := make([]byte, 1024)
		encryptedMessage := []string{}

		// Looping over received message parts (of 5 characters)
		for {
			n, err := (*connection).Read(buffer)

			if err != nil {

				// If the connection is closed remove it from the map, and return.
				if errors.Is(err, io.EOF) {

					delete(connectedClients, connectionId)
					log.Printf("Client %s has closed the connection.\n", connectionId)
					return

				} else {
					logger.Printf("error reading from client: %s", err.Error())
				}
			}

			if string(buffer[:n]) == "-1" {
				break
			} else {
				encryptedMessage = append(encryptedMessage, string(buffer[:n]))
			}

			// TODO: replace plaintext ack with an encrypted ack.
			n, err = (*connection).Write([]byte(ack))
			if (err != nil) || n != len(ack) {
				logger.Printf("error sending ack\n")
			}
		}

		// Decrypting the client's message using our own private key, printing it,
		// then re-encrypting it with when forwarding using each client's public key.
		decryptedMessage := util.Decrypt(encryptedMessage, D, N)
		log.Printf("Client %s: %s\n", connectionId, util.Decode(decryptedMessage))

		// Sending the message to other clients
		for id, client := range connectedClients {

			// skipping ourselves
			if id == connectionId {
				continue
			}

			reEncryptedMessage := util.Encrypt(append(encodedPidStr, decryptedMessage...), client.E, client.N)

			for _, chunk := range reEncryptedMessage {

				// Writing to the client's connection at the interclient socket.
				_, err := (*client.InterClientConnection).Write([]byte(chunk))
				if err != nil {
					logger.Printf("error writing to client: %s", err.Error())
				}

				// receive ack
				n, err := (*client.InterClientConnection).Read(ackBuffer)
				if err != nil || strings.Compare(string(ack[:n]), "1") != 0 {
					logger.Printf("error receiving ack\n")
				}

			}
			(*client.InterClientConnection).Write([]byte("-1"))
		}
	}
}
