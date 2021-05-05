/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:55
 * @Last Modified: U2, 2018-07-14 16:35:55
 */

package firewall

import (
	"encoding/json"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// RPCSelectVulntypes ...
func RPCSelectVulntypes() (vulnTypes []*models.VulnType) {
	rpcRequest := &models.RPCRequest{
		Action: "get_vuln_types", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCSelectVulntypes GetResponse", err)
		return nil
	}
	rpcVulnTypes := &models.RPCVulntypes{}
	if err := json.Unmarshal(resp, rpcVulnTypes); err != nil {
		utils.DebugPrintln("RPCSelectVulntypes Unmarshal", err)
		return nil
	}
	vulnTypes = rpcVulnTypes.Object
	return vulnTypes
}
