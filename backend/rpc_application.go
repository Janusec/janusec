/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:23:12
 * @Last Modified: U2, 2018-07-14 16:23:12
 */

package backend

import (
	"encoding/json"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

func RPCSelectApplications() (apps []*models.Application) {
	rpcRequest := &models.RPCRequest{Action: "getapps", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.CheckError("RPCSelectApplications GetResponse", err)
		return nil
	}
	rpcApps := new(models.RPCApplications)
	err = json.Unmarshal(resp, rpcApps)
	if err != nil {
		utils.CheckError("RPCSelectApplications Unmarshal", err)
		return nil
	}
	applications := rpcApps.Object
	return applications
}
