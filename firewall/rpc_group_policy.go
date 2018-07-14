/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:42
 * @Last Modified: U2, 2018-07-14 16:35:42
 */

package firewall

import (
	"encoding/json"

	"../data"
	"../models"
	"../utils"
)

func RPCSelectGroupPolicies() (group_policies []*models.GroupPolicy) {
	rpc_request := &models.RPCRequest{
		Action: "getgrouppolicies", Object: nil}
	resp, err := data.GetResponse(rpc_request)
	if err != nil {
		utils.CheckError("RPCSelectGroupPolicies GetResponse", err)
		return nil
	}
	rpc_group_policies := new(models.RPCGroupPolicies)
	if err := json.Unmarshal(resp, rpc_group_policies); err != nil {
		utils.CheckError("RPCSelectGroupPolicies Unmarshal", err)
		return nil
	}
	group_policies = rpc_group_policies.Object
	return group_policies
}
