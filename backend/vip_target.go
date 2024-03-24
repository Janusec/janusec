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

	"github.com/patrickmn/go-cache"
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
							SetVipTargetOffline(vTarget)
							return
						}
						// udpTargetConn will be closed in go thread
						udpTargetConn.SetDeadline(time.Now().Add(10 * time.Second))
						go func(udpConn *net.UDPConn, vipTarget *models.VipTarget) {
							data := make([]byte, 2048)
							_, _, err := udpConn.ReadFromUDP(data)
							if err != nil {
								SetVipTargetOffline(vipTarget)
							} else {
								vipTarget.Online = true
							}
							udpConn.Close()
						}(udpTargetConn, vTarget)

						// send test data to target
						_, err = udpTargetConn.Write([]byte("Hi"))
						if err != nil {
							SetVipTargetOffline(vTarget)
							return
						}
					}
				}(vipApp, target)
			}
		}
	}
}

func ContainsTargetID(targets []*models.VipTarget, targetID int64) bool {
	for _, target := range targets {
		if target.ID == targetID {
			return true
		}
	}
	return false
}

func SetVipTargetOffline(dest *models.VipTarget) {
	target := dest.Destination
	if dest.RouteType == models.K8S_Ingress {
		target = dest.PodsAPI
	}
	if count, ok := offlineCache.Get(target); !ok {
		offlineCache.Set(target, int64(1), cache.DefaultExpiration)
	} else {
		nowCount := count.(int64) + int64(1)
		if nowCount > 5 {
			// more than 5 requests timeout
			dest.Online = false
			app, err := GetVipAppByID(dest.VipAppID)
			if err == nil {
				sendVIPOfflineNotification(app, target)
			}
		}
		offlineCache.Set(target, nowCount, cache.DefaultExpiration)
	}
}

// sendVIPOfflineNotification ...
func sendVIPOfflineNotification(app *models.VipApp, dest string) {
	var emails string
	if data.IsPrimary {
		emails = data.DAL.GetAppAdminAndOwnerEmails(app.Owner)
	} else {
		emails = data.NodeSetting.SMTP.AdminEmails
	}
	mailBody := "Backend virtual IP: " + dest + " (" + app.Name + ") was offline."
	if len(mailBody) > 0 && len(emails) > 0 {
		go utils.SendEmail(data.NodeSetting.SMTP.SMTPServer,
			data.NodeSetting.SMTP.SMTPPort,
			data.NodeSetting.SMTP.SMTPAccount,
			data.NodeSetting.SMTP.SMTPPassword,
			emails,
			"[JANUSEC] Backend server offline notification",
			mailBody)
	}
}
