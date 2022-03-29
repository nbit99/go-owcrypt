package eddsa

import (
	"bytes"
	"crypto/rand"
	"github.com/nbit99/go-owcrypt/eddsa/edwards25519"
	"github.com/nbit99/go-owcrypt/sha3"
)


// GenerateKey generates a public/private key pair
func Ed25519Nem_genPub(prikey []byte) ([]byte, error) {

	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], prikey[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)

	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	return publicKeyBytes[:], nil

}

// Sign signs the message with privateKey and returns a signature.
func Ed25519Nem_sign(privateKey []byte, message []byte) ([]byte, error) {
	if l := len(privateKey); l != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	pubkey, err := ED25519_genPub(privateKey)
	if err != nil {
		return nil, ErrPrivateKeyIllegal
	}

	var  messageDigest, hramDigest [64]byte
	var expandedSecretKey, digest1 [32]byte

	copy(expandedSecretKey[:], privateKey[:])

	//expandedSecretKey[0] &= 248
	//expandedSecretKey[31] &= 63
	//expandedSecretKey[31] |= 64

	h := sha3.NewKeccak512()
	rand.Read(digest1[:])

	h.Write(digest1[:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(pubkey)
	h.Write(message)
	h.Sum(hramDigest[:0])

	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, 64)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature, nil
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Ed25519Nem_verify(publicKey []byte, message, sig []byte) bool {
	if l := len(publicKey); l != 32 {
		return false
	}

	if len(sig) != 64 || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha3.NewKeccak512()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
}

func reverseBytes(input []byte) []byte {
	output := make([]byte, len(input))

	j := len(input) - 1
	for i := 0; i < len(input); i++ {
		output[j] = input[i]
		j--
	}

	return output
}

