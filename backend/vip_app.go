/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-30 22:17:54
 * @Last Modified: U2, 2020-10-30 22:17:54
 */

package backend

import (
	"janusec/data"
	"janusec/models"
)

// VipApps : list of all port forwarding configuration
var VipApps = []*models.VipApp{}

// LoadVipApps load vip applications for port forwarding
func LoadVipApps() {
	VipApps = VipApps[0:0]
	if data.IsPrimary {
		dbApps := data.DAL.SelectVipApplications()
		for _, dbApp := range dbApps {
			vipApp := &models.VipApp{
				ID:          dbApp.ID,
				Name:        dbApp.Name,
				ListenPort:  dbApp.ListenPort,
				IsTCP:       dbApp.IsTCP,
				Targets:     []*models.VipTarget{},
				Owner:       dbApp.Owner,
				Description: dbApp.Description,
			}
			VipApps = append(VipApps, vipApp)
		}
		// Load VIP Targets
		for _, vipApp := range VipApps {
			vipApp.Targets = data.DAL.SelectVipTargetsByAppID(vipApp.ID)
		}
	} else {
		// Replica
		rpcVipApps := RPCSelectVipApplications()
		if rpcVipApps != nil {
			VipApps = rpcVipApps
		}
	}
}

// GetVipApps return list of all port forwarding configuration
func GetVipApps(authUser *models.AuthUser) ([]*models.VipApp, error) {
	if authUser.IsAppAdmin {
		return VipApps, nil
	}
	vipApps := []*models.VipApp{}
	return vipApps, nil
}
