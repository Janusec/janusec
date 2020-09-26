/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:13
 * @Last Modified: U2, 2018-07-14 16:35:13
 */

package firewall

import (
	"janusec/models"
)

// InitFirewall ...
func InitFirewall() {
	InitCCPolicy()
	ccPolicies.Range(func(key, value interface{}) bool {
		appID := key.(int64)
		ccPolicy := value.(*models.CCPolicy)
		if ccPolicy.IsEnabled == true {
			go CCAttackTick(appID)
		}
		return true
	})
	InitVulnType()
	InitGroupPolicy()
	LoadCheckItems()
	InitHitLog()
	InitNFTables()
	go RoutineCleanLogTick()
	go RoutineCleanCacheTick()
}
