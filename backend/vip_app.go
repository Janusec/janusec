/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-30 22:17:54
 * @Last Modified: U2, 2020-10-30 22:17:54
 */

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net"
	"strconv"
	"time"
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
	vipApp.ExitChan = make(chan bool)
	address := ":" + strconv.FormatInt(vipApp.ListenPort, 10)
	if vipApp.IsTCP {
		vipListener, err := net.Listen("tcp", address)
		if err != nil {
			utils.DebugPrintln("could not start server on port ", vipApp.ListenPort, err)
		}
		if vipListener != nil {
			defer vipListener.Close()
		}
		go TCPForwarding(vipApp, vipListener)
		// Waiting exit signal
		<-vipApp.ExitChan
		return
	}
	// UDP
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		utils.DebugPrintln("ResolveUDPAddr", address, err)
		return
	}
	udpListenConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		utils.DebugPrintln("ListenOnVIP could not start udp port ", vipApp.ListenPort, err)
	}
	if udpListenConn != nil {
		defer udpListenConn.Close()
	}
	// Mode: not use ListenUDP, when response uses service port
	go UDPForwarding(vipApp, udpListenConn)

	<-vipApp.ExitChan
}

// UDPForwarding with DialUDP
func UDPForwarding(vipApp *models.VipApp, udpListenConn *net.UDPConn) {
	for {
		dataBuf := make([]byte, 2048)
		dataInLen, clientAddr, err := udpListenConn.ReadFromUDP(dataBuf)
		if err != nil {
			//fmt.Println("UDPForwarding ReadMsgUDP", err)
			break
		}
		vipTarget := SelectVipTarget(vipApp, clientAddr.String())
		if vipTarget != nil {
			vipTarget.CheckTime = time.Now().Unix()
			targetAddr, _ := net.ResolveUDPAddr("udp", vipTarget.Destination)
			udpTargetConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				utils.DebugPrintln("UDPForwarding DialUDP could not connect to target", vipTarget.Destination, err)
				SetVipTargetOffline(vipTarget)
				break
			}
			if udpTargetConn == nil {
				break
			}
			defer udpTargetConn.Close()

			// Log to file
			proxyAddr := udpListenConn.LocalAddr().String()
			utils.VipAccessLog(vipApp.Name, clientAddr.String(), proxyAddr, vipTarget.Destination)

			udpTargetConn.SetDeadline(time.Now().Add(30 * time.Second))
			go func() {
				// make receiver ready before send request
				dataBuf := make([]byte, 2048)
				for {
					n, _, err := udpTargetConn.ReadFromUDP(dataBuf)
					if err != nil {
						SetVipTargetOffline(vipTarget)
						break
					}
					// Response to client
					_, err = udpListenConn.WriteToUDP(dataBuf[:n], clientAddr)
					if err != nil {
						break
					}
				}
			}()

			// forward to target
			_, err = udpTargetConn.Write(dataBuf[:dataInLen])
			if err != nil {
				utils.DebugPrintln("UDPForwarding to target", vipTarget.Destination, err)
				continue
			}
		}
	}
}

// TCPForwarding accept connections and forward to backend targets
func TCPForwarding(vipApp *models.VipApp, vipListener net.Listener) {
	for {
		if vipListener == nil {
			// fmt.Println("TCPForwarding vipListener nil, break")
			break
		}
		proxy, err := vipListener.Accept()
		if proxy == nil {
			// fmt.Println("TCPForwarding proxy nil, break")
			break
		}
		if err != nil {
			utils.DebugPrintln("TCPForwarding port forwarding: could not accept client connection", err)
		}
		remoteAddr := proxy.RemoteAddr()
		vipTarget := SelectVipTarget(vipApp, remoteAddr.String())
		if vipTarget != nil {
			targetDest := vipTarget.Destination
			// If K8S, get target Pod
			if vipTarget.RouteType == models.K8S_Ingress {
				targetDest = SelectPodFromVIPTarget(vipTarget, remoteAddr.String())
			}
			// Reverse Proxy
			target, err := net.Dial("tcp", targetDest)
			vipTarget.CheckTime = time.Now().Unix()
			if err != nil {
				utils.DebugPrintln("TCPForwarding could not connect to target", targetDest, err)
				SetVipTargetOffline(vipTarget)
				continue
			}
			vipTarget.Online = true
			// Log to file
			utils.VipAccessLog(vipApp.Name, remoteAddr.String(), proxy.LocalAddr().String(), targetDest)
			// stream copy
			go func() {
				io.Copy(target, proxy)
			}()
			go func() {
				io.Copy(proxy, target)
				proxy.Close()
				target.Close()
			}()
		} else {
			proxy.Close()
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

// UpdateVipApps refresh the object in the list
func UpdateVipApps(vipApp *models.VipApp) {
	for i, obj := range VipApps {
		if obj.ID == vipApp.ID {
			VipApps[i] = vipApp
		}
	}
}

// UpdateVipApp create or update VipApp for port forwarding
func UpdateVipApp(body []byte, clientIP string, authUser *models.AuthUser) (*models.VipApp, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super admin can configure port forwarding")
	}
	var rpcVipAppRequest *models.APIVipAppRequest
	if err := json.Unmarshal(body, &rpcVipAppRequest); err != nil {
		fmt.Println("UpdateApplication", err)
		return nil, err
	}
	vipApp := rpcVipAppRequest.Object
	if vipApp.ListenPort <= 1024 {
		return nil, errors.New("port number must be greater than 1024")
	}

	if vipApp.ID == 0 {
		// new application
		vipApp.ID = data.DAL.InsertVipApp(vipApp.Name, vipApp.ListenPort, vipApp.IsTCP, vipApp.Owner, vipApp.Description)

		VipApps = append(VipApps, vipApp)
		go utils.OperationLog(clientIP, authUser.Username, "Add Port Forwarding", vipApp.Name)
	} else {
		// check exists
		oldVipApp, _ := GetVipAppByID(vipApp.ID)
		if oldVipApp != nil {
			// exist old vipApp
			err := data.DAL.UpdateVipAppByID(vipApp.Name, vipApp.ListenPort, vipApp.IsTCP, vipApp.Owner, vipApp.Description, vipApp.ID)
			if err != nil {
				utils.DebugPrintln("UpdateVipApp", err)
			}
			// exit old vipApp listen
			oldVipApp.ExitChan <- true
			// update old vipApp pointer in vipApps
			UpdateVipApps(vipApp)
			go utils.OperationLog(clientIP, authUser.Username, "Update Port Forwarding", vipApp.Name)
		} else {
			return nil, errors.New("port forwarding not found")
		}
	}
	// fmt.Println("update targets ...")
	UpdateTargets(vipApp, vipApp.Targets)
	vipListener, err := net.Listen("tcp", ":"+strconv.FormatInt(vipApp.ListenPort, 10))
	if err != nil {
		utils.DebugPrintln("could not start server on port ", vipApp.ListenPort, err)
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
func UpdateTargets(vipApp *models.VipApp, targets []*models.VipTarget) {
	for _, target := range vipApp.Targets {
		// delete outdated destinations from DB
		if !ContainsTargetID(targets, target.ID) {
			err := data.DAL.DeleteVipTargetByID(target.ID)
			if err != nil {
				utils.DebugPrintln("DeleteVipTargetByID", err)
			}
		}
	}
	var newTargets = []*models.VipTarget{}

	for _, target := range targets {
		// add new destinations to DB and app
		var err error
		if target.ID == 0 {
			target.ID, err = data.DAL.InsertVipTarget(vipApp.ID, int64(target.RouteType), target.Destination, target.PodsAPI, target.PodPort)
			if err != nil {
				utils.DebugPrintln("InsertVipTarget", err)
			}
		} else {
			err = data.DAL.UpdateVipTarget(vipApp.ID, int64(target.RouteType), target.Destination, target.PodsAPI, target.PodPort, target.ID)
			if err != nil {
				utils.DebugPrintln("UpdateVipTarget", err)
			}
		}
		target.Online = true
		newTargets = append(newTargets, target)
	}
	vipApp.Targets = newTargets
}

// DeleteVipAppByID delete port forwarding
func DeleteVipAppByID(id int64, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin {
		return errors.New("you have no privilege to delete it")
	}
	DeleteVipTargetsByAppID(id)
	err := data.DAL.DeleteVipAppByID(id)
	if err != nil {
		utils.DebugPrintln("DeleteVipAppByID ", err)
		return err
	}
	i := GetVipAppIndex(id)
	VipApps[i].ExitChan <- true
	go utils.OperationLog(clientIP, authUser.Username, "Delete Port Forwarding", VipApps[i].Name)
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
