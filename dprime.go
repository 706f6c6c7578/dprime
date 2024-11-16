package main

import (
	"crypto/sha512"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

func main() {
	password := flag.String("p", "", "Password for prime generation")
	salt := flag.String("s", "", "Salt for prime generation")
	bits := flag.Int("size", 1024, "Size of prime in bits (min: 512, recommended: 1024-4096)")
	hexOutput := flag.Bool("h", false, "Output prime in hexadecimal format")
	flag.Parse()

	if *password == "" || *salt == "" {
		fmt.Printf("Usage: dprime -p <password> -s <salt> [-size <bits>] [-h hex output]\n")
		return
	}

	// Validate bit size
	if *bits < 512 {
		fmt.Printf("Bit size must be at least 512.\n")
		return
	}

	// Warning for very large numbers
	if *bits > 8192 {
		fmt.Printf("Warning: Large bit sizes may take significant time to compute\n")
	}

	prime := generatePrime(*password, *salt, *bits)
	
	if *hexOutput {
		fmt.Printf("Generated %d-bit Prime (hex): %X\n", *bits, prime.Bytes())
	} else {
		fmt.Printf("Generated %d-bit Prime (decimal): %s\n", *bits, prime.String())
	}
}

func deriveKey(password, salt string) []byte {
	// Argon2id Parameter
	time := uint32(1)
	memory := uint32(64 * 1024)
	threads := uint8(4)
	keyLen := uint32(32)

	// Derive key using Argon2id
	argonKey := argon2.IDKey([]byte(password), []byte(salt), time, memory, threads, keyLen)

	// Initialize HKDF with SHA-512
	hkdfReader := hkdf.New(sha512.New, argonKey, []byte(salt), []byte("PrimeGeneration"))
	
	finalKey := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, finalKey); err != nil {
		panic(err)
	}

	return finalKey
}

func generatePrime(password, salt string, bits int) *big.Int {
	// Derive key material using Argon2id and HKDF
	keyMaterial := deriveKey(password, salt)
	
	// Convert derived key to big integer
	seed := new(big.Int).SetBytes(keyMaterial)
	
	// Scale to desired bit size
	seed.Mul(seed, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(bits)), nil))
	
	// Find next prime number
	prime := new(big.Int)
	prime.SetBytes(seed.Bytes())
	
	// Ensure the number has exactly the requested bit size
	prime.SetBit(prime, bits-1, 1)
	
	// Ensure the number is odd
	if prime.Bit(0) == 0 {
		prime.Add(prime, big.NewInt(1))
	}
	
	// Find next prime
	for !prime.ProbablyPrime(20) {
		prime.Add(prime, big.NewInt(2))
	}
	
	return prime
}
