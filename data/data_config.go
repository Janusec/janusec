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

	"github.com/Janusec/janusec/models"
	//"fmt"
)

func NewConfig(filename string) (*models.Config, error) {
	config := new(models.Config)
	config_bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(config_bytes, config)
	if strings.ToLower(config.NodeRole) == "master" {
		db_password := config.MasterNode.Database.Password
		if len(db_password) <= 32 {
			// Encrypt password
			encrypted_password_bytes := AES256Encrypt([]byte(db_password), true)
			encrypted_password := hex.EncodeToString(encrypted_password_bytes)
			encrypted_config := models.EncryptedConfig(*config)
			encrypted_config.MasterNode.Database.Password = encrypted_password
			encrypted_config_bytes, _ := json.MarshalIndent(encrypted_config, "", "\t")
			err = ioutil.WriteFile(filename, encrypted_config_bytes, 0644)
		} else {
			// Decrypt password
			encrypted_password, err := hex.DecodeString(db_password)
			if err != nil {
				return nil, err
			}
			password_bytes, _ := AES256Decrypt(encrypted_password, true)
			config.MasterNode.Database.Password = string(password_bytes)
		}
	}
	//fmt.Println("NewConfig config.Database.Password=",config.Database.Password)
	return config, nil
}
