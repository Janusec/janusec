/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-11-04 22:56:54
 * @Last Modified: U2, 2020-10-30 22:56:54
 */

package backend

import (
	"janusec/data"
	"janusec/models"
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
			if !target.Online {
				go func(vApp *models.VipApp, vTarget *models.VipTarget) {
					var conn net.Conn
					var err error
					if vApp.IsTCP {
						conn, err = net.DialTimeout("tcp", vTarget.Destination, time.Second)
						if err == nil {
							defer conn.Close()
							vTarget.Online = true
							vTarget.CheckTime = nowTimeStamp
						}
					} else {
						targetAddr, _ := net.ResolveUDPAddr("udp", vTarget.Destination)
						udpTargetConn, err := net.DialUDP("udp", nil, targetAddr)
						if err != nil {
							vTarget.Online = false
							return
						}
						// udpTargetConn will be closed in go thread
						udpTargetConn.SetDeadline(time.Now().Add(10 * time.Second))
						go func(udpConn *net.UDPConn, vipTarget *models.VipTarget) {
							data := make([]byte, 2048)
							_, _, err := udpConn.ReadFromUDP(data)
							if err != nil {
								vipTarget.Online = false
							} else {
								vipTarget.Online = true
							}
							udpConn.Close()
						}(udpTargetConn, vTarget)

						// send test data to target
						_, err = udpTargetConn.Write([]byte("Hi"))
						if err != nil {
							vTarget.Online = false
							return
						}
					}
				}(vipApp, target)
			}
		}
	}
}
