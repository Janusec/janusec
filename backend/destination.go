/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:54
 * @Last Modified: U2, 2018-07-14 16:21:54
 */

package backend

import (
	"encoding/json"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	offlineCache = cache.New(30*time.Second, 30*time.Second)
)

// ContainsDestinationID ...
// destination example: [{"id":16,"route_type":1,"request_route":"/","backend_route":"/","destination":"127.0.0.1:8800","app_id":14,"node_id":0,"online":true,"check_time":0}]
func ContainsDestinationID(destinations []*models.Destination, destID int64) bool {
	for _, destination := range destinations {
		if destination.ID == destID {
			return true
		}
	}
	return false
}

// CheckOfflineDestinations check offline destinations and reset the online status
func CheckOfflineDestinations(nowTimeStamp int64) {
	for _, app := range Apps {
		for _, dest := range app.Destinations {
			dest.Mutex.Lock()
			defer dest.Mutex.Unlock()
			if dest.RouteType == models.ReverseProxyRoute && !dest.Online {
				go func(dest2 *models.Destination) {
					conn, err := net.DialTimeout("tcp", dest2.Destination, time.Second)
					if err == nil {
						defer conn.Close()
						dest2.Mutex.Lock()
						defer dest2.Mutex.Unlock()
						dest2.Online = true
						dest2.CheckTime = nowTimeStamp
					}
				}(dest)
			} else if dest.RouteType == models.K8S_Ingress && !dest.Online {
				// check k8s api
				request, _ := http.NewRequest("GET", dest.PodsAPI, nil)
				request.Header.Set("Content-Type", "application/json")
				resp, err := utils.GetResponse(request)
				if err != nil {
					dest.CheckTime = nowTimeStamp
					continue
				}
				pods := models.PODS{}
				err = json.Unmarshal(resp, &pods)
				if err != nil {
					utils.DebugPrintln("Unmarshal K8S API", err)
				}
				dest.Pods = ""
				for _, podItem := range pods.Items {
					if podItem.Status.Phase == "Running" {
						if len(dest.Pods) > 0 {
							dest.Pods += "|"
						}
						dest.Pods += podItem.Status.PodIP + ":" + dest.PodPort
					}
				}
				dest.CheckTime = nowTimeStamp
				dest.Online = true
			}
		}
	}
}

// SetDestinationOffline added on Mar 23, 2024, v1.5.0
func SetDestinationOffline(dest *models.Destination) {
	targetDest := dest.Destination
	if dest.RouteType == models.K8S_Ingress {
		targetDest = dest.PodsAPI
	}
	if count, ok := offlineCache.Get(targetDest); !ok {
		offlineCache.Set(targetDest, int64(1), cache.DefaultExpiration)
	} else {
		nowCount := count.(int64) + int64(1)
		if nowCount > 5 {
			// more than 5 requests timeout
			dest.Online = false
			app, err := GetApplicationByID(dest.AppID)
			if err == nil {
				sendOfflineNotification(app, targetDest)
			}
		}
		offlineCache.Set(targetDest, nowCount, cache.DefaultExpiration)
	}
}

// sendOfflineNotification ...
func sendOfflineNotification(app *models.Application, dest string) {
	var emails string
	if data.IsPrimary {
		emails = data.DAL.GetAppAdminAndOwnerEmails(app.Owner)
	} else {
		emails = data.NodeSetting.SMTP.AdminEmails
	}
	mailBody := "Backend server: " + dest + " (" + app.Name + ") was offline."
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
