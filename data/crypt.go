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
	// rootKey was generated by hex.EncodeToString(GenRandomAES256Key())
	rootKey, _ = hex.DecodeString("58309a83b94a93313a8de8f3ca815f709f4ea52066417b2ae592f2dbfd1c69ab")

	// instanceKey used for private key and ldap password encryption
	// when save instanceKey to database, it will be encrypted by rootKey
	instanceKey []byte

	// NodesKey shared between primary node and replica nodes
	// HexEncryptedNodesKey for replica nodes, show on admin UI
	// HexEncryptedNodesKey is the encrypted and hex string format of NodesKey
	// HexEncryptedNodesKey = hex.EncodeToString(AES256Encrypt(NodesKey, true))
	NodesKey []byte

	// DataDiscoveryKey used for reporting data discoveries to JANUCAT (Compliance, Accountability and Transparency)
	// DataDiscoveryKey = hex.DecodeString(NodeSetting.DataDiscoveryKey)
	DataDiscoveryKey []byte

	// APIKey used for external control panels, show on admin UI - settings. APIKey will not be shared with replica nodes
	// hexAPIKey = hex.EncodeToString(APIKey) , will be showed on admin UI
	APIKey []byte
)

// LoadInstanceKey ...
func (dal *MyDAL) LoadInstanceKey() {
	if !dal.ExistsSetting("instance_key") {
		instanceKey = GenRandomAES256Key()
		encryptedInstanceKey := AES256Encrypt(instanceKey, true)
		hexInstanceKey := hex.EncodeToString(encryptedInstanceKey)
		err := dal.SaveStringSetting("instance_key", hexInstanceKey)
		if err != nil {
			utils.DebugPrintln("LoadInstanceKey SaveStringSetting", err)
		}
	} else {
		hexEncryptedKey := dal.SelectStringSetting("instance_key")
		decodeEncryptedKey, _ := hex.DecodeString(hexEncryptedKey)
		instanceKey, _ = AES256Decrypt(decodeEncryptedKey, true)
	}
}

// LoadNodesKey only run on primary node
func (dal *MyDAL) LoadNodesKey() {
	if !dal.ExistsSetting("nodes_key") {
		NodesKey = GenRandomAES256Key()
		encryptedNodesKey := AES256Encrypt(NodesKey, true)
		hexEncryptedNodesKey := hex.EncodeToString(encryptedNodesKey)
		err := dal.SaveStringSetting("nodes_key", hexEncryptedNodesKey)
		if err != nil {
			utils.DebugPrintln("LoadNodesKey SaveStringSetting", err)
		}
	} else {
		var err error
		hexEncryptedNodesKey := dal.SelectStringSetting("nodes_key")
		decodeEncryptedKey, _ := hex.DecodeString(hexEncryptedNodesKey)
		NodesKey, err = AES256Decrypt(decodeEncryptedKey, true)
		if err != nil {
			utils.DebugPrintln("LoadNodesKey AES256Decrypt", err)
		}
	}
}

// GetHexEncryptedNodesKey return HexEncryptedKey which will be displayed on admin UI
func GetHexEncryptedNodesKey() *models.NodesKey {
	hexEncryptedNodesKey := hex.EncodeToString(AES256Encrypt(NodesKey, true))
	nodesKey := &models.NodesKey{HexEncryptedKey: hexEncryptedNodesKey}
	return nodesKey
}

// LoadAPIKey only run on primary node
func (dal *MyDAL) LoadAPIKey() {
	if !dal.ExistsSetting("api_key") {
		APIKey = GenRandomAES256Key()
		encryptedAPIKey := AES256Encrypt(APIKey, true)
		hexEncryptedAPIKey := hex.EncodeToString(encryptedAPIKey)
		err := dal.SaveStringSetting("api_key", hexEncryptedAPIKey)
		if err != nil {
			utils.DebugPrintln("LoadAPIKey SaveStringSetting", err)
		}
	} else {
		var err error
		hexEncryptedAPIKey := dal.SelectStringSetting("api_key")
		encryptedKey, _ := hex.DecodeString(hexEncryptedAPIKey)
		APIKey, err = AES256Decrypt(encryptedKey, true)
		if err != nil {
			utils.DebugPrintln("LoadAPIKey AES256Decrypt", err)
		}
	}
}

// GetHexAPIKey will return HEX format of APIKey without encryption
func GetHexAPIKey() *models.APIKey {
	hexAPIKey := hex.EncodeToString(APIKey)
	apiKey := &models.APIKey{HexAPIKey: hexAPIKey}
	return apiKey
}

// GenRandomAES256Key ...
func GenRandomAES256Key() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		utils.DebugPrintln("GenRandomAES256Key", err)
	}
	return key
}

// EncryptWithKey ...
func EncryptWithKey(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		utils.DebugPrintln("EncryptWithKey NewCipher", err)
	}
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		utils.DebugPrintln("EncryptWithKey ReadFull", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		utils.DebugPrintln("EncryptWithKey NewGCM", err)
	}
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

// AES256Encrypt ...
func AES256Encrypt(plaintext []byte, useRootkey bool) []byte {
	key := instanceKey
	if useRootkey {
		key = rootKey
	}
	ciphertext := EncryptWithKey(plaintext, key)
	return ciphertext
}

// DecryptWithKey ...
func DecryptWithKey(ciphertext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var err error
	block, err = aes.NewCipher(key)
	if err != nil {
		utils.DebugPrintln("DecryptWithKey NewCipher", err)
		return []byte{}, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		utils.DebugPrintln("DecryptWithKey NewGCM", err)
		return []byte{}, err
	}
	nonce, ciphertext := ciphertext[:12], ciphertext[12:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		utils.DebugPrintln("DecryptWithKey Open", err)
		return []byte{}, err
	}
	return plaintext, nil
}

// AES256Decrypt ...
func AES256Decrypt(ciphertext []byte, useRootkey bool) ([]byte, error) {
	key := instanceKey
	if useRootkey {
		key = rootKey
	}
	plaintext, err := DecryptWithKey(ciphertext, key)
	if err != nil {
		utils.DebugPrintln("AES256Decrypt", err)
	}
	return plaintext, err
}

// GetRandomSaltString ...
func GetRandomSaltString() string {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		utils.DebugPrintln("GetRandomSaltString", err)
	}
	saltStr := fmt.Sprintf("%x", salt)
	return saltStr
}

// SHA256Hash ...
func SHA256Hash(plaintext string) string {
	hash := sha256.New()
	_, err := hash.Write([]byte(plaintext))
	if err != nil {
		utils.DebugPrintln("SHA256Hash hash.Write", err)
	}
	result := fmt.Sprintf("%x", hash.Sum(nil))
	return result
}

// NodeHexKeyToCryptKey ...
func NodeHexKeyToCryptKey(hexKey string) []byte {
	encrptedKey, err := hex.DecodeString(hexKey)
	if err != nil {
		utils.DebugPrintln("NodeHexKeyToCryptKey DecodeString", err)
	}
	key, err := AES256Decrypt(encrptedKey, true)
	if err != nil {
		utils.DebugPrintln("NodeHexKeyToCryptKey AES256Decrypt", err)
	}
	return key
}

// CryptKeyToNodeHexKey ...
func CryptKeyToNodeHexKey(keyBytes []byte) string {
	encryptedKey := AES256Encrypt(keyBytes, true)
	hexKey := hex.EncodeToString(encryptedKey)
	return hexKey
}
