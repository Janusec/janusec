/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:42
 * @Last Modified: U2, 2018-07-14 16:35:42
 */

package firewall

import (
	"encoding/json"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// RPCSelectGroupPolicies ...
func RPCSelectGroupPolicies() (groupPolicies []*models.GroupPolicy) {
	rpcRequest := &models.RPCRequest{
		Action: "getgrouppolicies", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.CheckError("RPCSelectGroupPolicies GetResponse", err)
		return nil
	}
	rpcGroupPolicies := new(models.RPCGroupPolicies)
	if err := json.Unmarshal(resp, rpcGroupPolicies); err != nil {
		utils.CheckError("RPCSelectGroupPolicies Unmarshal", err)
		return nil
	}
	groupPolicies = rpcGroupPolicies.Object
	return groupPolicies
}
