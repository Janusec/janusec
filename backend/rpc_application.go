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

// RPCSelectApplications ...
func RPCSelectApplications() []*models.Application {
	rpcRequest := &models.RPCRequest{Action: "get_apps", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.CheckError("RPCSelectApplications GetResponse", err)
		return nil
	}
	rpcApps := &models.RPCApplications{}
	err = json.Unmarshal(resp, rpcApps)
	if err != nil {
		utils.CheckError("RPCSelectApplications Unmarshal", err)
		return nil
	}
	applications := rpcApps.Object
	return applications
}

// RPCSelectVipApplications VIP for port forwarding
func RPCSelectVipApplications() []*models.VipApp {
	rpcRequest := &models.RPCRequest{Action: "get_vip_apps", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.CheckError("RPCSelectVipApplications GetResponse", err)
		return nil
	}
	rpcVipApps := &models.RPCVipApps{}
	err = json.Unmarshal(resp, rpcVipApps)
	if err != nil {
		utils.CheckError("RPCSelectVipApplications Unmarshal", err)
		return nil
	}
	vipApps := rpcVipApps.Object
	return vipApps
}
