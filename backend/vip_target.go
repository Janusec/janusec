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
	"net"
	"time"
)

// DeleteVipTargetsByAppID delete backend targets for port forwarding
func DeleteVipTargetsByAppID(id int64) {
	err := data.DAL.DeleteVipTargetsByVipAppID(id)
	if err != nil {
		utils.DebugPrintln("DeleteVipTargetsByAppID", err)
	}
}

// CheckOfflineVipTargets check offline targets and reset the online status
func CheckOfflineVipTargets(nowTimeStamp int64) {
	for _, vipApp := range VipApps {
		for _, target := range vipApp.Targets {
			if target.Online == false {
				go func() {
					var conn net.Conn
					var err error
					if vipApp.IsTCP {
						conn, err = net.DialTimeout("tcp", target.Destination, time.Second)
					} else {
						conn, err = net.DialTimeout("udp", target.Destination, time.Second)
					}
					if err == nil {
						defer conn.Close()
						target.Online = true
						target.CheckTime = nowTimeStamp
					}
				}()
			}
		}
	}
}
