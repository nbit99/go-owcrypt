package owcrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
)

var bintZero = big.NewInt(0)
func zilSign(privateKey, k, message []byte) ([]byte, byte, error) {
	v := byte(0x01)

	if k == nil {
		err2 := errors.New("")
		k, err2 = GenerateRandomBytes(secp256k1.N.BitLen() / 8)
		if err2 != nil {
			return nil,v, err2
		}
	}

	priKey := new(big.Int).SetBytes(privateKey)
	bintK := new(big.Int).SetBytes(k)

	// 1a. check if private key is 0
	if priKey.Cmp(new(big.Int).SetInt64(0)) <= 0 {
		return nil, v, errors.New("private key must be > 0")
	}

	// 1b. check if private key is less than curve order, i.e., within [1...n-1]
	if priKey.Cmp(secp256k1.N) >= 0 {
		return nil, v, errors.New("private key cannot be greater than curve order")
	}

	if bintK.Cmp(bintZero) == 0 {
		return nil, v, errors.New("k cannot be zero")
	}

	if bintK.Cmp(secp256k1.N) > 0 {
		return nil, v, errors.New("k cannot be greater than order of secp256k1")
	}

	// 2. Compute commitment Q = kG, where G is the base point
	Qx, Qy := secp256k1.ScalarBaseMult(k)

	Q := Compress(secp256k1, Qx, Qy, true)

	// 3. Compute the challenge r = H(Q || pubKey || msg)
	// mod reduce r by the order of secp256k1, n

	publicKey,_ := genPublicKey(privateKey, "secp256k1")
	publicKey = PointCompress(publicKey, ECC_CURVE_SECP256K1)

	mHash := zilHash(Q, publicKey, message[:])
	fmt.Printf("msgHash keyBytes: %x \n", Q)
	fmt.Printf("msgHash pubKey: %x \n", publicKey)
	fmt.Printf("msgHash: %x \n", message)

	fmt.Printf("ecdsa msgHash: %x \n", mHash)

	r := new(big.Int).SetBytes(mHash)
	r = r.Mod(r, secp256k1.N)

	if r.Cmp(bintZero) == 0 {
		return nil, v, errors.New("invalid r")
	}

	//4. Compute s = k - r * prv
	// 4a. Compute r * prv
	_r := *r
	s := new(big.Int).Mod(_r.Mul(&_r, priKey), secp256k1.N)
	s = new(big.Int).Mod(new(big.Int).Sub(bintK, s), secp256k1.N)

	if s.Cmp(big.NewInt(0)) == 0 {
		return nil, v, errors.New("invalid s")
	}

	signature := make([]byte, 64)
	copy(signature[32-len(r.Bytes()):32], r.Bytes())
	copy(signature[64-len(s.Bytes()):64], s.Bytes())

	return signature, v, nil

}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func zilHash(Q []byte, pubKey []byte, msg []byte) []byte {
	var buffer bytes.Buffer
	buffer.Write(Q)
	buffer.Write(pubKey[:33])
	buffer.Write(msg)

	fmt.Printf("buffer2:%x \n", buffer.Bytes())
	msg2 := Hash(buffer.Bytes(), 0, HASH_ALG_SHA256)
	return msg2
}


func Compress(curve elliptic.Curve, x, y *big.Int, compress bool) []byte {
	return Marshal(curve, x, y, compress)
}

func Marshal(curve elliptic.Curve, x, y *big.Int, compress bool) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	if compress {
		ret := make([]byte, 1+byteLen)
		if y.Bit(0) == 0 {
			ret[0] = 2
		} else {
			ret[0] = 3
		}
		xBytes := x.Bytes()
		copy(ret[1+byteLen-len(xBytes):], xBytes)
		return ret
	}

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point
	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	yBytes := y.Bytes()
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	return ret
}


func verifyZil(publicKey []byte, msg []byte, signature []byte) bool {

	r := signature[:32]
	s := signature[32:]

	bintR := new(big.Int).SetBytes(r)
	bintS := new(big.Int).SetBytes(s)

	//cannot be zero
	if bintR.Cmp(bintZero) == 0 || bintS.Cmp(bintZero) == 0 {
		fmt.Printf("Invalid R or S value: cannot be zero")
		return false
	}

	//cannot be negative
	if bintR.Sign() == -1 || bintS.Sign() == -1 {
		fmt.Printf("Invalid R or S value: cannot be negative")
		return false
	}

	// cannot be greater than curve.N
	if bintR.Cmp(secp256k1.N) == 1 || bintS.Cmp(secp256k1.N) == 1 {
		fmt.Printf("Invalid R or S value: cannot be greater than order of secp256k1")
		return false
	}

	deCompressPubKey := publicKey

	if len(deCompressPubKey) < 64 {
		deCompressPubKey = PointDecompress(deCompressPubKey, ECC_CURVE_SECP256K1)
	}

	deCompressPubKey = deCompressPubKey[1:]

	if deCompressPubKey == nil || len(deCompressPubKey) != 64 {
		return false
	}

	pubk := new(ecdsa.PublicKey)
	pubk.Curve = secp256k1

	pubk.X = new(big.Int).SetBytes(deCompressPubKey[:32])
	pubk.Y = new(big.Int).SetBytes(deCompressPubKey[32:])

	lx, ly := secp256k1.ScalarMult(pubk.X, pubk.Y, r)
	rx, ry := secp256k1.ScalarBaseMult(s)
	Qx, Qy := secp256k1.Add(rx, ry, lx, ly)
	Q := Compress(secp256k1, Qx, Qy, true)

	_r := zilHash(Q, publicKey, msg)
	_rn := new(big.Int).Mod(new(big.Int).SetBytes(_r), secp256k1.N)

	rn := new(big.Int).SetBytes(r)
	return rn.Cmp(_rn) == 0
}