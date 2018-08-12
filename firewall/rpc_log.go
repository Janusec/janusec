/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:48
 * @Last Modified: U2, 2018-07-14 16:35:48
 */

package firewall

import (
	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func RPCGroupHitLog(regexHitLog *models.GroupHitLog) {
	rpc_request := &models.RPCRequest{
		Action: "log_group_hit", Object: regexHitLog}
	_, err := data.GetResponse(rpc_request)
	utils.CheckError("RPCRegexHitLog", err)
}

func RPCCCLog(ccLog *models.CCLog) {
	rpc_request := &models.RPCRequest{
		Action: "log_cc", Object: ccLog}
	_, err := data.GetResponse(rpc_request)
	utils.CheckError("RPCCCLog", err)
}
