/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:35
 * @Last Modified: U2, 2018-07-14 16:35:35
 */

package firewall

import (
	"encoding/json"

	"../data"
	"../models"
	"../utils"
)

func RPCSelectCCPolicies() (cc_policies []*models.CCPolicy) {
	rpc_request := &models.RPCRequest{
		Action: "getccpolicies", Object: nil}
	resp, err := data.GetResponse(rpc_request)
	if err != nil {
		utils.CheckError("RPCSelectCCPolicies GetResponse", err)
		return nil
	}
	rpc_cc_policies := new(models.RPCCCPolicies)
	if err := json.Unmarshal(resp, rpc_cc_policies); err != nil {
		utils.CheckError("RPCSelectCCPolicies Unmarshal", err)
		return nil
	}
	cc_policies = rpc_cc_policies.Object
	return cc_policies
}
