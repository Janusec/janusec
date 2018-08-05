/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:42
 * @Last Modified: U2, 2018-07-14 16:35:42
 */

package firewall

import (
	"encoding/json"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func RPCSelectGroupPolicies() (groupPolicies []*models.GroupPolicy) {
	rpcRequest := &models.RPCRequest{
		Action: "getgrouppolicies", Object: nil}
	resp, err := data.GetResponse(rpcRequest)
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
