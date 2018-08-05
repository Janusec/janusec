/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:19
 * @Last Modified: U2, 2018-07-14 16:31:19
 */

package data

import (
	"encoding/json"

	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func RPCGetSettings() []*models.Setting {
	rpcRequest := &models.RPCRequest{
		Action: "getsettings", Object: nil}
	resp, err := GetResponse(rpcRequest)
	utils.CheckError("RPCGetSettings", err)
	rpcSettings := new(models.RPCSettings)
	if err = json.Unmarshal(resp, rpcSettings); err != nil {
		utils.CheckError("RPCGetSettings Unmarshal", err)
	}
	return rpcSettings.Object
}
