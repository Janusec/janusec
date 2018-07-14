/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:19
 * @Last Modified: U2, 2018-07-14 16:21:19
 */

package settings

import (
	"time"

	"../backend"
	"../data"
	"../firewall"
)

var (
	update_ticker *time.Ticker
)

func UpdateTimeTick() {
	update_ticker = time.NewTicker(data.Sync_Seconds * time.Second)
	for range update_ticker.C {
		//fmt.Println("UpdateTimeTick:", time.Now())
		setting_items := data.RPCGetSettings()
		for _, setting_item := range setting_items {
			switch setting_item.Name {
			case "Backend_Last_Modified":
				new_backend_last_modified := int64(setting_item.Value.(float64))
				if data.Backend_Last_Modified < new_backend_last_modified {
					data.Backend_Last_Modified = new_backend_last_modified
					go backend.LoadAppConfiguration()
				}
			case "Firewall_Last_Modified":
				new_firewall_last_modified := int64(setting_item.Value.(float64))
				if data.Firewall_Last_Modified < new_firewall_last_modified {
					data.Firewall_Last_Modified = new_firewall_last_modified
					go firewall.InitFirewall()
				}
			case "Sync_Seconds":
				new_sync_seconds := time.Duration(setting_item.Value.(float64))
				if data.Sync_Seconds != new_sync_seconds {
					data.Sync_Seconds = new_sync_seconds
					update_ticker.Stop()
					update_ticker = time.NewTicker(data.Sync_Seconds * time.Second)
				}
			}
		}
	}
}
