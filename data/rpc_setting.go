/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:19
 * @Last Modified: U2, 2018-07-14 16:31:19
 */

package data

import (
	"encoding/json"

	"../models"
	"../utils"
)

func RPCGetSettings() []*models.Setting {
	rpc_request := &models.RPCRequest{
		Action: "getsettings", Object: nil}
	resp, err := GetResponse(rpc_request)
	utils.CheckError("RPCGetSettings", err)
	rpc_settings := new(models.RPCSettings)
	if err = json.Unmarshal(resp, rpc_settings); err != nil {
		utils.CheckError("RPCGetSettings Unmarshal", err)
	}
	return rpc_settings.Object
}
