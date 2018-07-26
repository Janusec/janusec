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

func RPCSelectVulntypes() (vuln_types []*models.VulnType) {
	rpc_request := &models.RPCRequest{
		Action: "getvulntypes", Object: nil}
	resp, err := data.GetResponse(rpc_request)
	if err != nil {
		utils.CheckError("RPCSelectVulntypes GetResponse", err)
		return nil
	}
	rpc_vuln_types := new(models.RPCVulntypes)
	if err := json.Unmarshal(resp, rpc_vuln_types); err != nil {
		utils.CheckError("RPCSelectVulntypes Unmarshal", err)
		return nil
	}
	vuln_types = rpc_vuln_types.Object
	return vuln_types
}
