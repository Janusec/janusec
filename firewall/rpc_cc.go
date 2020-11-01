/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:35
 * @Last Modified: U2, 2018-07-14 16:35:35
 */

package firewall

import (
	"encoding/json"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// RPCSelectCCPolicies ...
func RPCSelectCCPolicies() (ccPolicies []*models.CCPolicy) {
	rpcRequest := &models.RPCRequest{
		Action: "getccpolicies", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.CheckError("RPCSelectCCPolicies GetResponse", err)
		return nil
	}
	rpcCCPolicies := &models.RPCCCPolicies{}
	if err := json.Unmarshal(resp, rpcCCPolicies); err != nil {
		utils.CheckError("RPCSelectCCPolicies Unmarshal", err)
		return nil
	}
	ccPolicies = rpcCCPolicies.Object
	return ccPolicies
}
