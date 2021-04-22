/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:04
 * @Last Modified: U2, 2018-07-14 16:25:04
 */

package data

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strings"

	"janusec/models"
	"janusec/utils"
	//"fmt"
)

// NewConfig ...
func NewConfig(filename string) (*models.Config, error) {
	config := &models.Config{}
	configBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(configBytes, config)
	if err != nil {
		utils.DebugPrintln("NewConfig json.Unmarshal", err)
	}
	if strings.ToLower(config.NodeRole) == "primary" {
		dbPassword := config.PrimaryNode.Database.Password
		if len(dbPassword) <= 32 {
			// Encrypt password
			encryptedPasswordBytes := AES256Encrypt([]byte(dbPassword), true)
			encryptedPassword := hex.EncodeToString(encryptedPasswordBytes)
			encryptedConfig := models.EncryptedConfig(*config)
			encryptedConfig.PrimaryNode.Database.Password = encryptedPassword
			encryptedConfigBytes, _ := json.MarshalIndent(encryptedConfig, "", "\t")
			_ = ioutil.WriteFile(filename, encryptedConfigBytes, 0600)
		} else {
			// Decrypt password
			encryptedPassword, err := hex.DecodeString(dbPassword)
			if err != nil {
				return nil, err
			}
			passwordBytes, _ := AES256Decrypt(encryptedPassword, true)
			config.PrimaryNode.Database.Password = string(passwordBytes)
		}
	}
	//fmt.Println("NewConfig config.Database.Password=",config.Database.Password)
	// Init default listen port
	if len(config.ListenHTTP) == 0 {
		config.ListenHTTP = ":80"
	}
	if len(config.ListenHTTPS) == 0 {
		config.ListenHTTPS = ":443"
	}
	return config, nil
}
