// GrandSlam formulas and test vectors adapted from blacktop/ipsw
// cf37896883e8484aa9af171fd6bbbbeef981ea85, internal/srp/grandslam.go.
// See THIRD_PARTY.md for attribution and the MIT license.
package grandslam

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

const modulusHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

type srpClient struct{ secret, public *big.Int }
type srpProof struct{ m1, m2, key []byte }

func newSRP() (*srpClient, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.New("generate GrandSlam SRP secret")
	}
	defer clear(secret)
	return srpWithSecret(secret)
}

func srpWithSecret(secret []byte) (*srpClient, error) {
	a := new(big.Int).SetBytes(secret)
	if a.Sign() == 0 {
		return nil, errors.New("invalid GrandSlam SRP secret")
	}
	n, _ := new(big.Int).SetString(modulusHex, 16)
	return &srpClient{a, new(big.Int).Exp(big.NewInt(2), a, n)}, nil
}

func hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func passwordKey(password string, salt []byte, rounds int, protocol string) ([]byte, error) {
	if len(password) > 4096 || len(salt) == 0 || len(salt) > 1024 || rounds < 1 || rounds > 1_000_000 {
		return nil, errors.New("invalid GrandSlam password derivation parameters")
	}
	passwordHash := hash([]byte(password))
	defer clear(passwordHash)
	if protocol == "s2k_fo" {
		encoded := []byte(hex.EncodeToString(passwordHash))
		defer clear(encoded)
		return pbkdf2.Key(encoded, salt, rounds, 32, sha256.New), nil
	}
	if protocol != "s2k" {
		return nil, errors.New("unsupported GrandSlam password protocol")
	}
	return pbkdf2.Key(passwordHash, salt, rounds, 32, sha256.New), nil
}

func (c *srpClient) complete(username, password string, salt, server []byte, rounds int, protocol string) (*srpProof, error) {
	if len(username) > 4096 || len(server) == 0 || len(server) > 257 {
		return nil, errors.New("invalid GrandSlam SRP challenge")
	}
	n, _ := new(big.Int).SetString(modulusHex, 16)
	g := big.NewInt(2)
	b := new(big.Int).SetBytes(server)
	if new(big.Int).Mod(b, n).Sign() == 0 {
		return nil, errors.New("invalid GrandSlam server public key")
	}
	u := new(big.Int).SetBytes(hash(c.public.Bytes(), b.Bytes()))
	if u.Sign() == 0 {
		return nil, errors.New("invalid GrandSlam scrambling parameter")
	}
	derived, err := passwordKey(password, salt, rounds, protocol)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	// Unlike IDMSA, GSA hashes minimal A/B/S encodings. Only g is padded.
	gp := g.FillBytes(make([]byte, 256))
	k := new(big.Int).SetBytes(hash(n.Bytes(), gp))
	x := new(big.Int).SetBytes(hash(salt, hash([]byte(":"), derived)))
	v := new(big.Int).Exp(g, x, n)
	base := new(big.Int).Sub(b, new(big.Int).Mul(k, v))
	exponent := new(big.Int).Add(c.secret, new(big.Int).Mul(u, x))
	s := new(big.Int).Exp(base, exponent, n).Bytes()
	if len(s) == 0 {
		s = []byte{0}
	}
	defer clear(s)
	key := hash(s)
	xor := hash(n.Bytes())
	for i, value := range hash(gp) {
		xor[i] ^= value
	}
	m1 := hash(xor, hash([]byte(username)), salt, c.public.Bytes(), b.Bytes(), key)
	return &srpProof{m1, hash(c.public.Bytes(), m1, key), key}, nil
}

func (p *srpProof) decrypt(serverProof, encrypted []byte) ([]byte, error) {
	if subtle.ConstantTimeCompare(p.m2, serverProof) != 1 {
		return nil, errors.New("GrandSlam server proof verification failed")
	}
	if len(encrypted) < aes.BlockSize || len(encrypted) > responseLimit || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("invalid GrandSlam encrypted session")
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, p.key)
		_, _ = mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	key, iv := derive("extra data key:"), derive("extra data iv:")
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize GrandSlam session decryption")
	}
	plain := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(plain, encrypted)
	padding := int(plain[len(plain)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aes.BlockSize)
	for i := 1; i <= aes.BlockSize; i++ {
		valid &= subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(i, padding), subtle.ConstantTimeByteEq(plain[len(plain)-i], byte(padding)), 1)
	}
	if valid != 1 {
		clear(plain)
		return nil, errors.New("invalid GrandSlam session padding")
	}
	return plain[:len(plain)-padding], nil
}
