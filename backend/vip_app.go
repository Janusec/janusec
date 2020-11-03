/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-30 22:17:54
 * @Last Modified: U2, 2020-10-30 22:17:54
 */

package backend

import (
	"errors"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"strings"
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

// UpdateVipApp create or update VipApp for port forwarding
func UpdateVipApp(param map[string]interface{}) (*models.VipApp, error) {
	application := param["object"].(map[string]interface{})
	appID := int64(application["id"].(float64))
	appName := application["name"].(string)
	listenPort := int64(application["listen_port"].(float64))
	isTCP := application["is_tcp"].(bool)
	var description string
	var ok bool
	if description, ok = application["description"].(string); !ok {
		description = ""
	}
	owner := application["owner"].(string)
	var app *models.VipApp
	if appID == 0 {
		// new application
		newID := data.DAL.InsertVipApp(appName, listenPort, isTCP, owner, description)
		app = &models.VipApp{
			ID:          newID,
			Name:        appName,
			ListenPort:  listenPort,
			IsTCP:       isTCP,
			Owner:       owner,
			Description: description,
		}
		VipApps = append(VipApps, app)
	} else {
		app, _ = GetVipAppByID(appID)
		if app != nil {
			err := data.DAL.UpdateVipAppByID(appName, listenPort, isTCP, owner, description, appID)
			if err != nil {
				utils.DebugPrintln("UpdateVipApp", err)
			}
			app.Name = appName
			app.ListenPort = listenPort
			app.IsTCP = isTCP
			app.Owner = owner
			app.Description = description
		} else {
			return nil, errors.New("Port Forwarding not found")
		}
	}
	targets := application["targets"].([]interface{})
	UpdateTargets(app, targets)
	data.UpdateBackendLastModified()
	return app, nil
}

// GetVipAppByID return the designated VipApp
func GetVipAppByID(id int64) (*models.VipApp, error) {
	for _, app := range VipApps {
		if app.ID == id {
			return app, nil
		}
	}
	return nil, errors.New("Not found.")
}

// UpdateTargets update the list of backend IP:Port
func UpdateTargets(vipApp *models.VipApp, targets []interface{}) {
	for _, target := range vipApp.Targets {
		// delete outdated destinations from DB
		if !InterfaceContainsDestinationID(targets, target.ID) {
			err := data.DAL.DeleteVipTargetByID(target.ID)
			if err != nil {
				utils.DebugPrintln("DeleteVipTargetByID", err)
			}
		}
	}
	var newTargets = []*models.VipTarget{}
	for _, targetInterface := range targets {
		// add new destinations to DB and app
		targetMap := targetInterface.(map[string]interface{})
		targetID := int64(targetMap["id"].(float64))
		destination := strings.TrimSpace(targetMap["destination"].(string))
		var err error
		if targetID == 0 {
			targetID, err = data.DAL.InsertVipTarget(vipApp.ID, destination)
			if err != nil {
				utils.DebugPrintln("InsertVipTarget", err)
			}
		} else {
			err = data.DAL.UpdateVipTarget(vipApp.ID, destination, targetID)
			if err != nil {
				utils.DebugPrintln("UpdateVipTarget", err)
			}
		}
		target := &models.VipTarget{
			ID:          targetID,
			VipAppID:    vipApp.ID,
			Destination: destination,
			Online:      true,
		}
		newTargets = append(newTargets, target)
	}
	vipApp.Targets = newTargets
}

func DeleteVipAppByID(id int64) error {
	app, err := GetVipAppByID(id)
	if err != nil {
		return err
	}
	DeleteTargetsByAppID(id)
	err = data.DAL.DeleteVipAppByID(id)
	if err != nil {
		utils.DebugPrintln("DeleteVipAppByID ", err)
		return err
	}
	i := GetVipAppIndex(id)
	VipApps = append(VipApps[:i], VipApps[i+1:]...)
	data.UpdateBackendLastModified()
	return nil
}
