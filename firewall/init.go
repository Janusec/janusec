/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:13
 * @Last Modified: U2, 2018-07-14 16:35:13
 */

package firewall

import (
	"../models"
)

func InitFirewall() {
	InitCCPolicy()
	cc_policies.Range(func(key, value interface{}) bool {
		app_id := key.(int64)
		cc_policy := value.(*models.CCPolicy)
		if cc_policy.IsEnabled == true {
			go CCAttackTick(app_id)
		}
		return true
	})
	InitVulnType()
	InitGroupPolicy()
	LoadCheckItems()
	InitHitLog()
	go RoutineTick()
}
