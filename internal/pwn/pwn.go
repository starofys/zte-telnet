package pwn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

var KEY_POOL = []byte{
	0x9c, 0x33, 0x75, 0xd1, 0x1c, 0x42, 0x45, 0x37, 0x18, 0x48,
	0x91, 0x73, 0x17, 0x45, 0x79, 0x44, 0x43, 0xd7, 0xd5, 0x73,
	0x33, 0x54, 0x76, 0xd2, 0xc5, 0xf1, 0x2c, 0x4f, 0x7a, 0xba,
	0x61, 0xd9, 0x5c, 0x69, 0xdf, 0x8c, 0xd2, 0x1c, 0xde, 0x3b,
	0x35, 0x2d, 0x2f, 0xe1, 0xde, 0x4c, 0x77, 0xf5, 0x1a, 0x65,
	0xd1, 0xfe, 0x18, 0x43, 0x8e, 0xa7, 0x42, 0x08, 0x04, 0x78,
	0xd5, 0xe4, 0xf3, 0x34, 0xa4, 0xd3, 0xf2, 0x36, 0x47, 0x6d,
	0x86, 0x9d, 0x42, 0x65, 0x13, 0x42, 0xdc, 0x42, 0x99, 0x48,
	0xdc, 0x67, 0x9f, 0x9e, 0xdc, 0x46, 0x37, 0x5f, 0x84, 0x9f,
	0x6f, 0x76, 0xce, 0x79, 0x4f, 0x49,
}

const (
	rsaN   = 30049
	rsaPhi = 29700
)

type PayloadStruct struct {
	Header        [4]uint32
	PonMac        [6]uint32
	ClientMac     [6]uint32
	ClientMacRend [6]uint32
	Key           [6]uint32
	KeyRend       [6]uint32
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func modPow(base, exp, mod uint32) uint32 {
	if mod == 1 {
		return 0
	}
	result := uint64(1)
	b := uint64(base % mod)
	e := uint64(exp)
	m := uint64(mod)
	for e > 0 {
		if e&1 == 1 {
			result = (result * b) % m
		}
		b = (b * b) % m
		e >>= 1
	}
	return uint32(result)
}

func modInverse(a, m uint32) uint32 {
	if gcd(a, m) != 1 {
		return 0
	}
	var x0, x1 int64 = 1, 0
	aa, mm := int64(a), int64(m)
	for mm != 0 {
		q := aa / mm
		aa, mm = mm, aa-q*mm
		x0, x1 = x1, x0-q*x1
	}
	if x0 < 0 {
		x0 += int64(m)
	}
	return uint32(x0)
}

func CreatePayloadArray(reRand uint32, serverMac, clientMac []byte, idx int) *PayloadStruct {
	if len(serverMac) < 6 || len(clientMac) < 6 {
		return nil
	}

	key := [6]byte{0x00, 0xFF, 0x72, 0x46, 0x34, 0x11}

	idxU := uint32(idx)

	var accum uint32 = 1
	for i := 0; i < 6; i++ {
		val1 := idxU + uint32(serverMac[i])
		val2 := reRand ^ val1
		accum = accum * val2
	}
	rsaSeed := accum & 0x1FFF

	var (
		s0, s1, s2 uint32 = 1, 0, 1
		eDyn, dDyn uint32
		found      bool
	)

	for attempt := 0; attempt < 100; attempt++ {
		tempS0 := uint32(2)
		tempS1 := uint32(attempt)
		tempS2 := uint32(2)
		eDyn = (tempS0 * rsaSeed) + tempS1

		if gcd(eDyn, rsaPhi) == 1 && eDyn >= 3 && eDyn < 100000 {
			s0, s1, s2 = tempS0, tempS1, tempS2
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	eDyn = (s0 * rsaSeed) + s1
	dDyn = modInverse(eDyn, rsaPhi)
	s3 := rsaN - ((s2 * rsaSeed) % rsaN)

	buffer := &PayloadStruct{}

	buffer.Header[0] = modPow(s0, 103, rsaN)
	buffer.Header[1] = modPow(s1, 103, rsaN)
	buffer.Header[2] = modPow(s2, 103, rsaN)
	buffer.Header[3] = modPow(s3, 103, rsaN)

	for i := 0; i < 6; i++ {
		buffer.PonMac[i] = modPow(uint32(serverMac[i]), dDyn, rsaN)
	}
	for i := 0; i < 6; i++ {
		buffer.ClientMac[i] = modPow(uint32(clientMac[i]), dDyn, rsaN)
	}
	buffer.ClientMacRend = buffer.ClientMac

	for i := 0; i < 6; i++ {
		buffer.Key[i] = modPow(uint32(key[i]), dDyn, rsaN)
	}
	buffer.KeyRend = buffer.Key

	return buffer
}

func ParseMac(inputStr string) ([]byte, error) {
	cleaned := strings.ReplaceAll(inputStr, ":", "")
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("invalid mac: %s", inputStr)
	}
	rawBytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid mac: %s", inputStr)
	}
	if len(rawBytes) != 6 {
		return nil, fmt.Errorf("invalid mac: %s", inputStr)
	}
	return rawBytes, nil
}

func GenerateAesKey(index int) cipher.Block {
	endIndex := index + 24
	if endIndex > len(KEY_POOL) {
		endIndex = len(KEY_POOL)
	}

	selectedKeys := KEY_POOL[index:endIndex]
	aesKey := make([]byte, len(selectedKeys))

	for i, x := range selectedKeys {
		aesKey[i] = (x ^ 0xA5) & 0xFF
	}

	b := createAesEcbCipher(aesKey)
	return b
}

func createAesEcbCipher(aesKey []byte) cipher.Block {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err) // 或者适当处理错误
	}
	return block
}

func BuildPayloadString(p *PayloadStruct) string {
	if p == nil {
		return ""
	}

	vals := make([]uint32, 0, 34)
	vals = append(vals, p.Header[:]...)
	vals = append(vals, p.PonMac[:]...)
	vals = append(vals, p.ClientMac[:]...)
	vals = append(vals, p.ClientMacRend[:]...)
	vals = append(vals, p.Key[:]...)
	vals = append(vals, p.KeyRend[:]...)

	payloadBytes := make([]byte, len(vals)*4)
	for i, val := range vals {
		binary.LittleEndian.PutUint32(payloadBytes[i*4:(i+1)*4], val)
	}

	payloadStr := string(payloadBytes)
	return fmt.Sprintf("SendInfo.gch?info=%d|%s", len(vals), payloadStr)
}

func EncryptAES(block cipher.Block, data []byte) ([]byte, error) {
	// 使用零填充
	blockSize := block.BlockSize()
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == blockSize {
		paddingLen = 0
	}

	// 填充零字节
	for i := 0; i < paddingLen; i++ {
		data = append(data, 0)
	}

	// ECB模式加密
	ciphertext := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], data[i:i+blockSize])
	}

	return ciphertext, nil
}

func DecryptAES(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data)%blockSize != 0 {
		paddingLen := blockSize - (len(data) % blockSize)
		for i := 0; i < paddingLen; i++ {
			data = append(data, 0)
		}
	}

	plaintext := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], data[i:i+blockSize])
	}

	// 移除零填充
	for len(plaintext) > 0 && plaintext[len(plaintext)-1] == 0 {
		plaintext = plaintext[:len(plaintext)-1]
	}

	return plaintext, nil
}
