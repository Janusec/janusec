/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:48
 * @Last Modified: U2, 2018-07-14 16:35:48
 */

package firewall

import (
	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// RPCGroupHitLog ...
func RPCGroupHitLog(regexHitLog *models.GroupHitLog) {
	rpcRequest := &models.RPCRequest{
		Action: "log_group_hit", Object: regexHitLog}
	_, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCRegexHitLog", err)
	}
}

// RPCCCLog ...
func RPCCCLog(ccLog *models.CCLog) {
	rpcRequest := &models.RPCRequest{
		Action: "log_cc", Object: ccLog}
	_, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCCCLog", err)
	}
}
