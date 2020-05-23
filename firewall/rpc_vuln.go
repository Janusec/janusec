/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:55
 * @Last Modified: U2, 2018-07-14 16:35:55
 */

package firewall

import (
	"encoding/json"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

// RPCSelectVulntypes ...
func RPCSelectVulntypes() (vulnTypes []*models.VulnType) {
	rpcRequest := &models.RPCRequest{
		Action: "getvulntypes", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.CheckError("RPCSelectVulntypes GetResponse", err)
		return nil
	}
	rpcVulnTypes := new(models.RPCVulntypes)
	if err := json.Unmarshal(resp, rpcVulnTypes); err != nil {
		utils.CheckError("RPCSelectVulntypes Unmarshal", err)
		return nil
	}
	vulnTypes = rpcVulnTypes.Object
	return vulnTypes
}
