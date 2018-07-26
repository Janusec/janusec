/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:15
 * @Last Modified: U2, 2018-07-14 16:25:15
 */

package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/Janusec/janusec/utils"
)

var (
	root_key, _  = hex.DecodeString("58309a83b94a93313a8de8f3ca815f709f4ea52066417b2ae592f2dbfd1c69ab")
	instance_key []byte
)

func (dal *MyDAL) LoadInstanceKey() {
	if dal.ExistsSetting("instance_key") == false {
		instance_key = GenRandomAES256Key()
		encrypted_instance_key := AES256Encrypt(instance_key, true)
		hex_instance_key := hex.EncodeToString(encrypted_instance_key)
		dal.SaveStringSetting("instance_key", hex_instance_key)
	} else {
		hex_encrypted_key, err := dal.SelectStringSetting("instance_key")
		utils.CheckError("LoadInstanceKey", err)
		decode_encrypted_key, _ := hex.DecodeString(hex_encrypted_key)
		instance_key, err = AES256Decrypt(decode_encrypted_key, true)
		utils.CheckError("LoadInstanceKey AES256Decrypt", err)
	}
}

func GenRandomAES256Key() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		utils.CheckError("GenRandomAES256Key", err)
	}
	return key
}

func EncryptWithKey(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	utils.CheckError("EncryptWithKey NewCipher", err)
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	utils.CheckError("EncryptWithKey ReadFull", err)
	aesgcm, err := cipher.NewGCM(block)
	utils.CheckError("EncryptWithKey NewGCM", err)
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

func AES256Encrypt(plaintext []byte, use_rootkey bool) []byte {
	key := instance_key
	if use_rootkey == true {
		key = root_key
	}
	ciphertext := EncryptWithKey(plaintext, key)
	return ciphertext
}

func DecryptWithKey(ciphertext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var err error
	block, err = aes.NewCipher(key)
	utils.CheckError("DecryptWithKey NewCipher", err)
	if err != nil {
		return []byte{}, err
	}
	aesgcm, err := cipher.NewGCM(block)
	utils.CheckError("DecryptWithKey NewGCM", err)
	if err != nil {
		return []byte{}, err
	}
	nonce, ciphertext := ciphertext[:12], ciphertext[12:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	utils.CheckError("DecryptWithKey Open", err)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, nil
}

func AES256Decrypt(ciphertext []byte, use_rootkey bool) ([]byte, error) {
	key := instance_key
	if use_rootkey == true {
		key = root_key
	}
	plaintext, err := DecryptWithKey(ciphertext, key)
	return plaintext, err
}

func GetRandomSaltString() string {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	utils.CheckError("GetRandomSaltString", err)
	salt_str := fmt.Sprintf("%x", salt)
	return salt_str
}

func SHA256Hash(plaintext string) string {
	hash := sha256.New()
	hash.Write([]byte(plaintext))
	result := fmt.Sprintf("%x", hash.Sum(nil))
	return result
}

func NodeHexKeyToCryptKey(hex_key string) []byte {
	encrpted_key, err := hex.DecodeString(hex_key)
	utils.CheckError("NodeHexKeyToCryptKey DecodeString", err)
	key, err := AES256Decrypt(encrpted_key, true)
	utils.CheckError("NodeHexKeyToCryptKey AES256Decrypt", err)
	return key
}

func CryptKeyToNodeHexKey(key_bytes []byte) string {
	encrypted_key := AES256Encrypt(key_bytes, true)
	hex_key := hex.EncodeToString(encrypted_key)
	return hex_key
}
