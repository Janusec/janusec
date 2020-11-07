/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-30 22:17:54
 * @Last Modified: U2, 2020-10-30 22:17:54
 */

package backend

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net"
	"strconv"
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
				ExitChan:    make(chan bool),
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
	// Start Port Forwarding
	for _, vipApp := range VipApps {
		go ListenOnVIP(vipApp)

	}
}

// ListenOnVIP ...
func ListenOnVIP(vipApp *models.VipApp) {
	vipListener, err := net.Listen("tcp", ":"+strconv.FormatInt(vipApp.ListenPort, 10))
	if err != nil {
		utils.DebugPrintln("could not start server on port ", vipApp.ListenPort, err)
		fmt.Println("ListenOnVIP could not start server on port ", vipApp.ListenPort, vipListener, err)
	}
	if vipListener != nil {
		defer vipListener.Close()
	}
	go VIPForwarding(vipApp, vipListener)
	fmt.Println("Working", vipApp.Name, vipApp.ListenPort)
	<-vipApp.ExitChan
	fmt.Println("Exited:", vipApp.Name)
}

// VIPForwarding accept connections and forward to backend targets
func VIPForwarding(vipApp *models.VipApp, vipListener net.Listener) {
	for {
		fmt.Println("Waiting Accept")
		if vipListener == nil {
			break
		}
		proxy, err := vipListener.Accept()
		if proxy == nil {
			break
		}
		if err != nil {
			utils.DebugPrintln("port forwarding: could not accept client connection", err)
		}
		fmt.Println("Received data", proxy)

		defer proxy.Close()

		remoteAddr := proxy.RemoteAddr()
		fmt.Printf("client '%v' connected!\n", remoteAddr)

		vipTarget := SelectVipTarget(vipApp, remoteAddr.String())
		if vipTarget != nil {
			target, err := net.Dial("tcp", vipTarget.Destination)
			if err != nil {
				utils.DebugPrintln("could not connect to target", err)
			}
			defer target.Close()
			// Log to file
			utils.VipAccessLog(vipApp.Name, remoteAddr.String(), proxy.LocalAddr().String(), vipTarget.Destination)
			// stream copy
			go func() { io.Copy(target, proxy) }()
			go func() { io.Copy(proxy, target) }()
		}
	}
}

// SelectVipTarget will replace SelectDestination
func SelectVipTarget(vipApp *models.VipApp, srcIP string) *models.VipTarget {
	var onlineTargets = []*models.VipTarget{}
	for _, target := range vipApp.Targets {
		if target.Online {
			onlineTargets = append(onlineTargets, target)
		}
	}
	targetLen := uint32(len(onlineTargets))
	if targetLen == 0 {
		return nil
	}
	var target *models.VipTarget
	if targetLen == 1 {
		target = onlineTargets[0]
	} else if targetLen > 1 {
		// According to Hash(IP)
		h := fnv.New32a()
		_, err := h.Write([]byte(srcIP))
		if err != nil {
			utils.DebugPrintln("SelectVipTarget h.Write", err)
		}
		hashUInt32 := h.Sum32()
		targetIndex := hashUInt32 % targetLen
		target = onlineTargets[targetIndex]
	}
	return target
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
	listenPort := int64(application["listen_port"].(float64))
	if listenPort <= 1024 {
		return nil, errors.New("port number must be greater than 1024")
	}
	appID := int64(application["id"].(float64))
	appName := application["name"].(string)

	isTCP := application["is_tcp"].(bool)
	var description string
	var ok bool
	if description, ok = application["description"].(string); !ok {
		description = ""
	}
	owner := application["owner"].(string)
	var vipApp *models.VipApp
	if appID == 0 {
		// new application
		newID := data.DAL.InsertVipApp(appName, listenPort, isTCP, owner, description)
		vipApp = &models.VipApp{
			ID:          newID,
			Name:        appName,
			ListenPort:  listenPort,
			IsTCP:       isTCP,
			Owner:       owner,
			Description: description,
			ExitChan:    make(chan bool),
		}
		VipApps = append(VipApps, vipApp)
	} else {
		vipApp, _ = GetVipAppByID(appID)
		if vipApp != nil {
			err := data.DAL.UpdateVipAppByID(appName, listenPort, isTCP, owner, description, appID)
			if err != nil {
				utils.DebugPrintln("UpdateVipApp", err)
			}
			vipApp.Name = appName
			vipApp.ListenPort = listenPort
			vipApp.IsTCP = isTCP
			vipApp.Owner = owner
			vipApp.Description = description
			fmt.Println("send exit signal to", vipApp.Name)
			vipApp.ExitChan <- true
			fmt.Println("sended exit signal to", vipApp.Name)
		} else {
			return nil, errors.New("Port Forwarding not found")
		}
	}
	fmt.Println("update targets ...")
	targets := application["targets"].([]interface{})
	UpdateTargets(vipApp, targets)
	vipListener, err := net.Listen("tcp", ":"+strconv.FormatInt(vipApp.ListenPort, 10))
	if err != nil {
		utils.DebugPrintln("could not start server on port ", vipApp.ListenPort, err)
		fmt.Println("UpdateVipApp could not start server on port ", vipApp.ListenPort, vipListener, err)
	}
	if vipListener != nil {
		vipListener.Close()
	}
	go ListenOnVIP(vipApp)
	data.UpdateBackendLastModified()
	return vipApp, err
}

// GetVipAppByID return the designated VipApp
func GetVipAppByID(id int64) (*models.VipApp, error) {
	for _, app := range VipApps {
		if app.ID == id {
			return app, nil
		}
	}
	return nil, errors.New("not found")
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

// DeleteVipAppByID delete port forwarding
func DeleteVipAppByID(id int64) error {
	DeleteVipTargetsByAppID(id)
	err := data.DAL.DeleteVipAppByID(id)
	if err != nil {
		utils.DebugPrintln("DeleteVipAppByID ", err)
		return err
	}
	i := GetVipAppIndex(id)
	VipApps[i].ExitChan <- true
	VipApps = append(VipApps[:i], VipApps[i+1:]...)
	data.UpdateBackendLastModified()
	return nil
}

// GetVipAppIndex find the VipApp index in slice
func GetVipAppIndex(vipAppID int64) int {
	for i := 0; i < len(VipApps); i++ {
		if VipApps[i].ID == vipAppID {
			return i
		}
	}
	return -1
}
