/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:54
 * @Last Modified: U2, 2018-07-14 16:21:54
 */

package backend

import (
	"encoding/json"
	"janusec/models"
	"janusec/utils"
	"net"
	"net/http"
	"time"
)

// InterfaceContainsDestinationID ...
// destination example: [{"id":16,"route_type":1,"request_route":"/","backend_route":"/","destination":"127.0.0.1:8800","app_id":14,"node_id":0,"online":true,"check_time":0}]
func InterfaceContainsDestinationID(destinations []interface{}, destID int64) bool {
	for _, destination := range destinations {
		destMap := destination.(map[string]interface{})
		id := int64(destMap["id"].(float64))
		if id == destID {
			return true
		}
	}
	return false
}

// CheckOfflineDestinations check offline destinations and reset the online status
func CheckOfflineDestinations(nowTimeStamp int64) {
	for _, app := range Apps {
		for _, dest := range app.Destinations {
			if dest.RouteType == models.ReverseProxyRoute && !dest.Online {
				go func(dest *models.Destination) {
					conn, err := net.DialTimeout("tcp", dest.Destination, time.Second)
					if err == nil {
						defer conn.Close()
						dest.Online = true
						dest.CheckTime = nowTimeStamp
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
