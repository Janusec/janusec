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

	"janusec/models"
	"janusec/utils"
)

var (
	RootKey, _           = hex.DecodeString("58309a83b94a93313a8de8f3ca815f709f4ea52066417b2ae592f2dbfd1c69ab")
	instanceKey          []byte
	NodesKey             []byte
	HexEncryptedNodesKey string
)

func (dal *MyDAL) LoadInstanceKey() {
	if dal.ExistsSetting("instance_key") == false {
		instanceKey = GenRandomAES256Key()
		encryptedInstanceKey := AES256Encrypt(instanceKey, true)
		hexInstanceKey := hex.EncodeToString(encryptedInstanceKey)
		dal.SaveStringSetting("instance_key", hexInstanceKey)
	} else {
		hexEncryptedKey, err := dal.SelectStringSetting("instance_key")
		utils.CheckError("LoadInstanceKey", err)
		decodeEncryptedKey, _ := hex.DecodeString(hexEncryptedKey)
		instanceKey, err = AES256Decrypt(decodeEncryptedKey, true)
		utils.CheckError("LoadInstanceKey AES256Decrypt", err)
	}
}

func (dal *MyDAL) LoadNodesKey() {
	if dal.ExistsSetting("nodes_key") == false {
		NodesKey = GenRandomAES256Key()
		encryptedNodesKey := AES256Encrypt(NodesKey, true)
		HexEncryptedNodesKey = hex.EncodeToString(encryptedNodesKey)
		dal.SaveStringSetting("nodes_key", HexEncryptedNodesKey)
	} else {
		var err error
		HexEncryptedNodesKey, err = dal.SelectStringSetting("nodes_key")
		utils.CheckError("LoadNodesKey", err)
		decodeEncryptedKey, _ := hex.DecodeString(HexEncryptedNodesKey)
		NodesKey, err = AES256Decrypt(decodeEncryptedKey, true)
		utils.CheckError("LoadNodesKey AES256Decrypt", err)
	}
}

func GetHexEncryptedNodesKey() *models.NodesKey {
	nodesKey := &models.NodesKey{HexEncryptedKey: HexEncryptedNodesKey}
	return nodesKey
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

func AES256Encrypt(plaintext []byte, useRootkey bool) []byte {
	key := instanceKey
	if useRootkey == true {
		key = RootKey
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

func AES256Decrypt(ciphertext []byte, useRootkey bool) ([]byte, error) {
	key := instanceKey
	if useRootkey == true {
		key = RootKey
	}
	plaintext, err := DecryptWithKey(ciphertext, key)
	return plaintext, err
}

func GetRandomSaltString() string {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	utils.CheckError("GetRandomSaltString", err)
	saltStr := fmt.Sprintf("%x", salt)
	return saltStr
}

func SHA256Hash(plaintext string) string {
	hash := sha256.New()
	hash.Write([]byte(plaintext))
	result := fmt.Sprintf("%x", hash.Sum(nil))
	return result
}

func NodeHexKeyToCryptKey(hexKey string) []byte {
	encrptedKey, err := hex.DecodeString(hexKey)
	utils.CheckError("NodeHexKeyToCryptKey DecodeString", err)
	key, err := AES256Decrypt(encrptedKey, true)
	utils.CheckError("NodeHexKeyToCryptKey AES256Decrypt", err)
	return key
}

func CryptKeyToNodeHexKey(keyBytes []byte) string {
	encryptedKey := AES256Encrypt(keyBytes, true)
	hexKey := hex.EncodeToString(encryptedKey)
	return hexKey
}
