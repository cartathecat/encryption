package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// https://medium.com/@jcox250/password-hash-salt-using-golang-b041dc94cb72

/*
Credentials ...
*/
type Credentials struct {
	Username string
	Password []byte
	Key      string
}

/*
HashAndSalt ...
*/
func (c Credentials) HashAndSalt() (string, error) {

	hash, err := bcrypt.GenerateFromPassword(c.Password, bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil

}

/*
CompareHash ...
*/
func CompareHash(orig string, pass []byte) (bool, error) {

	byteHash := []byte(orig)
	err := bcrypt.CompareHashAndPassword(byteHash, pass)
	if err != nil {
		return false, err
	}

	return true, nil

}

/*
DecryptString ...
*/
func (c Credentials) DecryptBytes() ([]byte, error) {

	newKeyString, err := hashTo32Bytes(c.Key)
	cipherText, _ := base64.URLEncoding.DecodeString(string(c.Password))

	block, err := aes.NewCipher([]byte(newKeyString))
	if err != nil {
		panic(err)
	}
	fmt.Println("Lengh of cipherText is: ", len(cipherText))
	fmt.Println("aes.BlockSize is: ", aes.BlockSize)

	if len(cipherText) < aes.BlockSize {
		panic("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	//return string(cipherText), nil
	return cipherText, nil
}

/*
EncryptString ...
*/
func (c Credentials) EncryptBytes() ([]byte, error) {

	newKeyString, err := hashTo32Bytes(c.Key)
	if err != nil {
		return nil, err
	}

	key := []byte(newKeyString)
	value := c.Password
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cipherText := make([]byte, aes.BlockSize+len(value))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherText[aes.BlockSize:], value)

	fmt.Println("Password is :", base64.URLEncoding.EncodeToString(cipherText))
	//return base64.URLEncoding.EncodeToString(cipherText), nil
	return cipherText, nil

}

/*
Sha1 ...
*/
func (c Credentials) Sha256() []byte {

	hash := sha256.New()

	hash.Write(c.Password)
	bs := hash.Sum(nil)
	fmt.Printf("Sha256 :%x\n", bs)

	return bs
}

/*
hashTo32Bytes ...
*/
func hashTo32Bytes(input string) (string, error) {

	if len(input) == 0 {
		return "", errors.New("No input")
	}
	//[]byte(c.Username)
	hasher := sha256.New()
	hasher.Write([]byte(input))
	stringToSHA256 := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	fmt.Println("Encrypt - Orig: ", stringToSHA256)
	return stringToSHA256[:32], nil

}

/*
Obfuscate ...

func (c *Neo4jCredentials) Obfuscate() []byte {
	out := ""
	for i := 0; i < len(c.User); i++ {
		out += string(c.User[i] ^ c.Key[i%len(c.Key)])
	}
	return []byte(out)
}
*/

/*
Encrypt ...

func (c *Neo4jCredentials) Encrypt() string {
	//	s := "Password"
	hash := sha1.New()
	hash.Write([]byte(c.Username))
	sha1hash := hex.EncodeToString(hash.Sum(nil))
	fmt.Println(c.Username, sha1hash)
	return sha1hash
}
*/

/*
private function
createHash ...

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	sha1hash := hex.EncodeToString(hasher.Sum(nil))
	//fmt.Println(key, sha1hash)
	return sha1hash
}
*/

/*
Encrypt1 ...

func Encrypt1(data []byte, passphrase string) []byte {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}
*/

/*
Decrypt ...

func Decrypt(data []byte, passphrase string) []byte {
	//data []byte
	//data := hex.EncodeToString(b)
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}
*/

// https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/

// Hello function
func Hello() string {
	fmt.Println("Call to Neo4j driver")
	return "Hello, from encryption module"
}
