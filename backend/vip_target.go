/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-11-04 22:56:54
 * @Last Modified: U2, 2020-10-30 22:56:54
 */

package backend

import (
	"janusec/data"
	"janusec/utils"
)

// DeleteVipTargetsByAppID delete backend targets for port forwarding
func DeleteVipTargetsByAppID(id int64) {
	err := data.DAL.DeleteVipTargetsByVipAppID(id)
	if err != nil {
		utils.DebugPrintln("DeleteVipTargetsByAppID", err)
	}
}
