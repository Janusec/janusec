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

// UpdateTimeTick Get Settings from Primary Node
func UpdateTimeTick() {
	updateTicker = time.NewTicker(data.SyncSeconds * time.Second)
	for range updateTicker.C {
		//fmt.Println("UpdateTimeTick:", time.Now())
		settingItems := data.RPCGetSettings()
		for _, settingItem := range settingItems {
			switch settingItem.Name {
			case "backend_last_modified":
				newBackendLastModified := int64(settingItem.Value.(float64))
				if data.BackendLastModified < newBackendLastModified {
					data.BackendLastModified = newBackendLastModified
					go backend.LoadAppConfiguration()
				}
			case "firewall_last_modified":
				newFirewallLastModified := int64(settingItem.Value.(float64))
				if data.FirewallLastModified < newFirewallLastModified {
					data.FirewallLastModified = newFirewallLastModified
					go firewall.InitFirewall()
				}
			case "sync_seconds":
				newSyncSeconds := time.Duration(settingItem.Value.(float64))
				if data.SyncSeconds != newSyncSeconds {
					data.SyncSeconds = newSyncSeconds
					updateTicker.Stop()
					updateTicker = time.NewTicker(data.SyncSeconds * time.Second)
				}
			}
		}
	}
}
