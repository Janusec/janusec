/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:30
 * @Last Modified: U2, 2018-07-14 16:35:30
 */

package firewall

import (
	"time"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/utils"
)

/*
Clear Expired Logs
*/
func RoutineTick() {
	if data.IsMaster {
		logExpireSeconds, err := data.DAL.SelectIntSetting("Log_Expire_Seconds")
		utils.CheckError("RoutineTick", err)
		//fmt.Println("RoutineTick log_expire_seconds:", log_expire_seconds)
		routineTicker := time.NewTicker(time.Duration(5*60) * time.Second)
		for range routineTicker.C {
			//fmt.Println("RoutineTick", time.Now())
			expiredTime := time.Now().Unix() - logExpireSeconds
			data.DAL.DeleteHitLogsBeforeTime(expiredTime)
			data.DAL.DeleteCCLogsBeforeTime(expiredTime)
		}
	}
}
