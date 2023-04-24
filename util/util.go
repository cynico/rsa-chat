package encode_decode

import (
	cr "crypto/rand"
	"log"
	"math"
	"math/big"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var encodingMap = map[rune]uint{
	'0': 0,
	'1': 1,
	'2': 2,
	'3': 3,
	'4': 4,
	'5': 5,
	'6': 6,
	'7': 7,
	'8': 8,
	'9': 9,
	'a': 10,
	'b': 11,
	'c': 12,
	'd': 13,
	'e': 14,
	'f': 15,
	'g': 16,
	'h': 17,
	'i': 18,
	'j': 19,
	'k': 20,
	'l': 21,
	'm': 22,
	'n': 23,
	'o': 24,
	'p': 25,
	'q': 26,
	'r': 27,
	's': 28,
	't': 29,
	'u': 30,
	'v': 31,
	'w': 32,
	'x': 33,
	'y': 34,
	'z': 35,
	' ': 36,
}
var decodingMap = map[uint]rune{
	0:  '0',
	1:  '1',
	2:  '2',
	3:  '3',
	4:  '4',
	5:  '5',
	6:  '6',
	7:  '7',
	8:  '8',
	9:  '9',
	10: 'a',
	11: 'b',
	12: 'c',
	13: 'd',
	14: 'e',
	15: 'f',
	16: 'g',
	17: 'h',
	18: 'i',
	19: 'j',
	20: 'k',
	21: 'l',
	22: 'm',
	23: 'n',
	24: 'o',
	25: 'p',
	26: 'q',
	27: 'r',
	28: 's',
	29: 't',
	30: 'u',
	31: 'v',
	32: 'w',
	33: 'x',
	34: 'y',
	35: 'z',
	36: ' ',
}

// Takes a string of length 5 characters and returns the encoded number,
func Encode(m string) []string {

	// appending spaces to the string, length is multiple of 5
	if remainder := len(m) % 5; remainder != 0 {
		m = m + strings.Repeat(" ", 5-remainder)
	}

	// making a slice of uint(s)
	encoded := make([]string, len(m)/5)

	// replacing special characters with white space.
	m = regexp.MustCompile(`[^a-zA-Z0-9 ]+`).ReplaceAllString(m, " ")

	// converting the whole string to lowercase
	m = strings.ToLower(m)

	for i := 0; i < len(m)/5; i++ {
		var encodedI uint = 0
		for j := 0; j < 5; j++ {
			encodedI += encodingMap[rune(m[5*i+j])] * uint(math.Pow(37, float64(4-j)))
		}
		encoded[i] = strconv.FormatInt(int64(encodedI), 10)
	}

	return encoded
}

// Takes an encode
func Decode(encodedMessage []string) string {

	m := ""

	for _, encodedChunk := range encodedMessage {

		e, _ := strconv.ParseInt(encodedChunk, 10, 0)
		x := uint(e)

		for j := 4; j >= 0; j-- {
			power := uint(math.Pow(37, float64(j)))
			quotient := x / power
			x = x - quotient*uint(math.Pow(37, float64(j)))
			m = m + string(decodingMap[quotient])
		}
	}

	return m
}

// Takes a list of encoded strings to encrypt with the provided E, N.
// Returns a list of the encrypted chunks (originally chunks of 5 characters), and
// a boolean, which is true if no problem is encountered
func Encrypt(m []string, E, N big.Int) []string {

	var C, M big.Int
	encrypted := make([]string, len(m))

	for i, chunk := range m {

		M.SetString(chunk, 10)
		C.Exp(&M, &E, &N)

		encrypted[i] = C.String()
	}

	return encrypted
}

// Takes a list of encrypted strings to decrypt with the provided D, N.
func Decrypt(c []string, D, N big.Int) []string {

	var C, M big.Int
	decrypted := make([]string, len(c))

	for i, chunk := range c {

		C.SetString(chunk, 10)
		M.Exp(&C, &D, &N)

		decrypted[i] = M.String()

	}

	return decrypted
}

// Generates and returns: E, D, N. In THAT order.
// Takes bits to decide the number of bits of private key d.
func GenerateKeyPair(bits int, logger *log.Logger) (big.Int, big.Int, big.Int) {

	e := big.NewInt(65537)
	var ϕn, d, n big.Int
	// We loop and only break when ϕn is coprime with e
	for {

		// Generating random prime p and q.
		pq := GenerateRandomPrime(2, bits/2)

		// Calculating n = p * q
		n.Mul(pq[0], pq[1])

		// Calculate (p-1), (q-1)
		pq[0].Sub(pq[0], big.NewInt(1))
		pq[1].Sub(pq[1], big.NewInt(1))

		// Calculating ϕ(n) = (p-1) * (q-1)
		ϕn.Mul(pq[0], pq[1])

		// Check if e is coprime to ϕn. If not: regenerate n/ϕn (p,q), and try again.
		if IsCoPrime(e, &ϕn) {
			break
		}
	}

	// Generate d, the inverse of e modulo ϕn.
	d.ModInverse(e, &ϕn)

	logger.Printf("length of the generated private key (d): %d bits\n", len(d.Text(2)))

	return *e, d, n
}

// IsCoPrime checks whether a and b are coprime or not.
func IsCoPrime(x *big.Int, y *big.Int) bool {

	zero := big.NewInt(0)

	var intermediate, a, b big.Int
	a.Set(x)
	b.Set(y)

	for b.Cmp(zero) != 0 {
		intermediate.Set(&b)
		b.Mod(&a, &b)
		a.Set(&intermediate)
	}

	// returns true if the gcd(a, b) == 1
	return a.Cmp(big.NewInt(1)) == 0
}

// Generate k random prime numbers of length bits.
func GenerateRandomPrime(k int, bits int) []*big.Int {

	generatedPrimes := make([]*big.Int, k)

	// Generate random primes.
	for i := 0; i < k; i++ {

		generatedPrimes[i], _ = cr.Prime(cr.Reader, bits)

		// Testing the generated number with n=40 tests.
		// Probability that it's not prime is (0.25)^n
		for !generatedPrimes[i].ProbablyPrime(40) {
			generatedPrimes[i], _ = cr.Prime(cr.Reader, bits)
		}

	}

	return generatedPrimes
}

// Takes a connection, sends the provided key pair, and receives acknowledgment on sending the key.
func SendKeyPair(connection *net.Conn, key []big.Int) bool {

	buffer := make([]byte, 1024)

	for _, toSend := range key {

		// Start the exchange.
		// Send n/e and receive acknowledgement.
		_, err := (*connection).Write([]byte(toSend.String()))
		if err != nil {
			log.Printf("error send key: %s\n", err.Error())
			return false
		}

		// Receive the acknowledgement.
		len, err := (*connection).Read(buffer)
		if err != nil {
			log.Printf("error receiving acknowledgement for key: %s\n", err.Error())
			return false
		}

		// Convert and make sure the acknowledgement is valid.
		var received big.Int
		if _, ok := received.SetString(string(buffer[:len]), 10); !ok {
			log.Printf("error converting acknowledgement for key; invalid ack: %s\n", err.Error())
			return false
		} else if received.Cmp(&toSend) != 0 {
			log.Printf("acknowledgement failed. received != sent\n")
			return false
		}

	}

	return true
}

// Takes a connection, returns the sent key, and sends an acknowledgment on receiving the key.
func ReceiveKeyPair(connection *net.Conn) ([]big.Int, bool) {

	buffer := make([]byte, 1024)
	receivedKey := make([]big.Int, 2)

	for i := 0; i < 2; i++ {

		// Start the exchange.
		// Receive and send acknowledgement.
		len, err := (*connection).Read(buffer)
		if err != nil {
			log.Printf("error exchanging with server: %s\n", err.Error())
			return nil, false
		}

		// Send the acknowledgement
		_, err = (*connection).Write(buffer[:len])
		if err != nil {
			log.Printf("error send acknowledgement to server: %s\n", err.Error())
			return nil, false
		}

		receivedKey[i].SetString(string(buffer[:len]), 10)

	}

	return receivedKey, true
}

// This part is only for random string generation, to generate plaintexts of the plain-cipher pairs
// in the attack program.
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func GenerateRandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
