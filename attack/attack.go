package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	util "rsa-util"
	"runtime"
	"sync"
)

var plaintext, ciphertext []string
var logger = log.Default()

var foundChannelMutex, dMutex sync.Mutex
var privateKeyBruteForced big.Int
var foundChannel = make(chan int, 1)

func Copy(s *big.Int) *big.Int {
	var c big.Int
	c.Set(s)
	return &c
}

// This function tries to find two prime factors (p, q) of n.
func findFactorsOfN(n big.Int) (pfs []*big.Int) {

	logger.Println("Attempting to find factors of n. To try bruteforce instead, pass the `-bruteforce` flag to the binary.")

	var sqrtOfN big.Int
	var quotient, mod big.Int

	sqrtOfN.Sqrt(&n)
	quotient.Set(&n)

	// Constants to use later.
	zero := big.NewInt(0)
	two := big.NewInt(2)

	quotient.DivMod(&n, two, &mod)
	if mod.Cmp(zero) == 0 {
		pfs = append(pfs, Copy(two), Copy(&quotient))
		return pfs
	}

	for i := big.NewInt(3); i.Cmp(&sqrtOfN) == -1; i.Add(i, two) {

		quotient.DivMod(&n, i, &mod)

		if mod.Cmp(zero) == 0 {

			// Appending the divisor and the quotient
			pfs = append(pfs, Copy(i))
			pfs = append(pfs, Copy(&quotient))

			// Found the two prime factors, break.
			break

		} else {
			quotient.Set(&n)
		}
	}

	return pfs
}

// This function employs bruteforce against the private key d.
// It checks with the pairs of plaintext-ciphertext given.
func bruteForce(n big.Int, begin big.Int, end big.Int, plaintext []string, ciphertext []string) {

	runtime.LockOSThread()

	one := big.NewInt(1)
	found := false

	var d big.Int
	d.Set(&begin)

	for ; d.Cmp(&end) == -1; d.Add(&d, one) {

		fmt.Printf("\rremaining: %s", d.Text(10))

		decrypted := util.Decrypt(ciphertext, d, n)
		for i, dec := range decrypted {

			if dec == plaintext[i] {
				if i == len(decrypted)-1 {
					found = true
				}
				continue
			} else {
				break
			}
		}

		if found {

			foundChannelMutex.Lock()
			dMutex.Lock()

			privateKeyBruteForced.Set(&d)
			foundChannel <- 1

			foundChannelMutex.Unlock()
			dMutex.Unlock()

		}
	}

	runtime.UnlockOSThread()
}

// Setting the number of threads to use in init function.
func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {

	bruteforceFlag := flag.Bool("bruteforce", false, "A flag to control whether to perform bruteforce, or to try factoring n.")
	privateKeySizeFlag := flag.Int("private-key-size", 30, "Specify the private key size.")

	flag.Parse()

	// If the default value is used.
	if *privateKeySizeFlag == 30 {
		logger.Println("Note: You can specify the size of the private key by passing the size to the flag `-private-key-size=20`")
	}

	e, d, n := util.GenerateKeyPair(*privateKeySizeFlag, logger)

	logger.Println("Values of e, d, n: ", e.Text(10), d.Text(10), n.Text(10))
	fmt.Println()

	// Preparing the plaintext-ciphertext pairs
	plaintext = util.Encode(util.GenerateRandomString(100))
	ciphertext = util.Encrypt(plaintext, e, n)

	if *bruteforceFlag {

		logger.Printf("Attempting bruteforce. Searching private key space up to: 2^%d\n", *privateKeySizeFlag)

		// Calculating chunk size
		var chunk, max big.Int
		max.Exp(big.NewInt(2), big.NewInt(int64(*privateKeySizeFlag)), nil)

		chunk.Div(&max, big.NewInt(int64(runtime.NumCPU())))

		for i := 0; i < runtime.NumCPU(); i++ {

			var begin, end big.Int

			begin.Mul(big.NewInt(int64(i)), &chunk)
			if i == runtime.NumCPU()-1 {
				end.Set(&max)
			} else {
				end.Mul(big.NewInt(int64(i+1)), &chunk)
			}

			logger.Printf("Started a thread to search the space in the range: [%s, %s[\n", begin.Text(10), end.Text(10))
			go bruteForce(n, begin, end, plaintext, ciphertext)
		}

		<-foundChannel
		logger.Println("Found private key: ", privateKeyBruteForced.Text(10))
	} else {
		primeFactors := findFactorsOfN(n)
		logger.Printf("Found prime factors of n [p, q]: %s , %s\n", primeFactors[0].Text(10), primeFactors[1].Text(10))
		logger.Println("p * q = ", primeFactors[0].Mul(primeFactors[0], primeFactors[1]).Text(10))
	}
}
