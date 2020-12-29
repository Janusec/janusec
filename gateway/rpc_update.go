/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:19
 * @Last Modified: U2, 2018-07-14 16:21:19
 */

package gateway

import (
	"time"

	"janusec/backend"
	"janusec/data"
	"janusec/firewall"
)

var (
	updateTicker *time.Ticker
)

func UpdateTimeTick() {
	updateTicker = time.NewTicker(data.Sync_Seconds * time.Second)
	for range updateTicker.C {
		//fmt.Println("UpdateTimeTick:", time.Now())
		settingItems := data.RPCGetSettings()
		for _, settingItem := range settingItems {
			switch settingItem.Name {
			case "Backend_Last_Modified":
				newBackendLastModified := int64(settingItem.Value.(float64))
				if data.Backend_Last_Modified < newBackendLastModified {
					data.Backend_Last_Modified = newBackendLastModified
					go backend.LoadAppConfiguration()
				}
			case "Firewall_Last_Modified":
				newFirewallLastModified := int64(settingItem.Value.(float64))
				if data.Firewall_Last_Modified < newFirewallLastModified {
					data.Firewall_Last_Modified = newFirewallLastModified
					go firewall.InitFirewall()
				}
			case "Sync_Seconds":
				newSyncSeconds := time.Duration(settingItem.Value.(float64))
				if data.Sync_Seconds != newSyncSeconds {
					data.Sync_Seconds = newSyncSeconds
					updateTicker.Stop()
					updateTicker = time.NewTicker(data.Sync_Seconds * time.Second)
				}
			}
		}
	}
}
