/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:13
 * @Last Modified: U2, 2018-07-14 16:35:13
 */

package firewall

import (
	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// InitFirewall ...
func InitFirewall() {
	utils.DebugPrintln("InitFirewall")
	InitCCPolicy()
	ccPolicies.Range(func(key, value interface{}) bool {
		appID := key.(int64)
		ccPolicy := value.(*models.CCPolicy)
		if ccPolicy.IsEnabled {
			go CCAttackTick(appID)
		}
		return true
	})
	InitVulnType()
	InitGroupPolicy()
	InitIPPolicies()
	LoadCheckItems()
	InitHitLog()
	InitNFTables()
	go RoutineCleanLogTick()
	go RoutineCleanCacheTick()

	// v1.4.2fix4
	dal := data.DAL
	if data.IsPrimary && !dal.ExistColumnInTable("ip_policies", "create_time") {
		err := dal.ExecSQL(`
ALTER TABLE "ip_policies" ADD COLUMN "create_time" BIGINT;
ALTER TABLE "ip_policies" ADD COLUMN "description" VARCHAR(1024) DEFAULT '';
`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE ip_policies add COLUMN", err)
		}
	}
}
