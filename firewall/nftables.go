/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-09-26 13:06:51
 * @Last Modified: U2, 2020-09-26 13:06:51
 */

package firewall

import (
	"janusec/utils"
	"net"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

var conn *nftables.Conn
var table *nftables.Table
var chain *nftables.Chain
var set *nftables.Set

// InitNFTables Create Table janusec, chain input
// nft add table inet janusec
// nft add chain inet janusec input  { type filter hook input priority 0\; }
// nft add set inet janusec blocklist {type ipv4_addr\; flags timeout\; }
// nft add rule inet janusec input ip saddr @blocklist drop
// nft add rule inet janusec input tcp dport { 80, 443 } accept
func InitNFTables() {
	//fmt.Println("InitNFTables")
	conn = &nftables.Conn{}
	table = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "janusec",
	})

	chain = conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	set = &nftables.Set{
		Table:      table,
		Name:       "blocklist",
		HasTimeout: true,
		KeyType:    nftables.TypeIPAddr,
	}
	err := conn.AddSet(set, []nftables.SetElement{})
	if err != nil {
		utils.DebugPrintln("InitNFTables AddSet error", err)
		return
	}
	rules, err := conn.GetRule(table, chain)
	if len(rules) == 0 {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        set.Name,
					SetID:          set.ID,
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}
	err = conn.Flush()
	if err != nil {
		utils.CheckError("nftables init error", err)
	}
}

// AddIP2NFTables add Source IP Address to Nftables Block list
// nft add element inet janusec blocklist { 192.168.100.1 timeout 300s }
func AddIP2NFTables(ip string, blockSeconds float64) {
	//fmt.Println("AddIP2NFTables", ip)
	rules, err := conn.GetRule(table, chain)
	if len(rules) == 0 {
		InitNFTables()
	}
	err = conn.SetAddElements(set, []nftables.SetElement{
		{Key: []byte(net.ParseIP(ip).To4()), Timeout: time.Duration(blockSeconds) * time.Second},
	})
	if err != nil {
		utils.CheckError("AddIP2NFTables SetAddElements error", err)
	}
	err = conn.Flush()
	if err != nil {
		utils.CheckError("AddIP2NFTables flush error", err)
	}
}
