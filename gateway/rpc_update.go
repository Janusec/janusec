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
	"janusec/utils"
)

var (
	// syncTicker used for check update from primary node
	syncTicker *time.Ticker
)

// SyncTimeTick let replica nodes get/sync NodeSettings from Primary Node
func SyncTimeTick() {
	utils.DebugPrintln("SyncTimeTick init:", data.NodeSetting.SyncInterval)
	syncTicker = time.NewTicker(data.NodeSetting.SyncInterval)
	for range syncTicker.C {
		//fmt.Println("SyncTimeTick:", time.Now())
		lastBackendModified := data.NodeSetting.BackendLastModified
		lastFirewallModified := data.NodeSetting.FirewallLastModified
		lastSyncInterval := data.NodeSetting.SyncInterval
		data.NodeSetting = data.RPCGetNodeSetting()
		// Check update
		if lastBackendModified < data.NodeSetting.BackendLastModified {
			go backend.LoadAppConfiguration()
		}
		if lastFirewallModified < data.NodeSetting.FirewallLastModified {
			go firewall.InitFirewall()
		}
		if lastSyncInterval != data.NodeSetting.SyncInterval {
			syncTicker.Stop()
			syncTicker = time.NewTicker(data.NodeSetting.SyncInterval)
			utils.DebugPrintln("SyncTimeTick change sync interval to:", data.NodeSetting.SyncInterval)
		}
	}
}
