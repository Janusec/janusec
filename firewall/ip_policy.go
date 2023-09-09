/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2021-01-10 12:16:51
 * @Last Modified: U2, 2021-01-10 12:16:51
 */

package firewall

import (
	"encoding/json"
	"errors"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"strconv"
	"time"
)

var globalIPPolicies []*models.IPPolicy

// InitIPPolicies load IP Policies to memory
func InitIPPolicies() {
	if data.IsPrimary {
		data.DAL.CreateTableIfNotExistsIPPolicies()
		globalIPPolicies = data.DAL.LoadIPPolicies()
		return
	}
	// Replica nodes
	globalIPPolicies = RPCLoadIPPolicies()
}

// GetIPPolicies return Allow List and Block List
func GetIPPolicies() ([]*models.IPPolicy, error) {
	return globalIPPolicies, nil
}

// UpdateIPPolicy update IP policy
func UpdateIPPolicy(body []byte, clientIP string, authUser *models.AuthUser) (*models.IPPolicy, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcIPRequest models.APIIPPolicyRequest
	if err := json.Unmarshal(body, &rpcIPRequest); err != nil {
		utils.DebugPrintln("UpdateIPPolicy", err)
		return nil, err
	}
	ipPolicy := rpcIPRequest.Object
	if ipPolicy.ID == 0 {
		// New IP
		ipPolicy.CreateTime = time.Now().Unix()
		ipPolicy.ID = data.DAL.InsertIPPolicy(ipPolicy.IPAddr, ipPolicy.IsAllow, ipPolicy.ApplyToWAF, ipPolicy.ApplyToCC, ipPolicy.CreateTime, ipPolicy.Description)
		globalIPPolicies = append(globalIPPolicies, ipPolicy)
		go utils.OperationLog(clientIP, authUser.Username, "Add IP Policy", ipPolicy.IPAddr)
		data.UpdateFirewallLastModified()
		return ipPolicy, nil
	}
	// Update
	err := data.DAL.UpdateIPPolicy(ipPolicy.ID, ipPolicy.IPAddr, ipPolicy.IsAllow, ipPolicy.ApplyToWAF, ipPolicy.ApplyToCC, ipPolicy.Description)
	if err != nil {
		utils.DebugPrintln("UpdateIPPolicy", err)
		return nil, err
	}
	globalIPPolicies = data.DAL.LoadIPPolicies()
	go utils.OperationLog(clientIP, authUser.Username, "Update IP Policy", ipPolicy.IPAddr)
	data.UpdateFirewallLastModified()
	return ipPolicy, nil
}

// DeleteIPPolicyByID ...
func DeleteIPPolicyByID(id int64, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin {
		return errors.New("only super administrators can perform this operation")
	}
	for i, ipPolicy := range globalIPPolicies {
		if ipPolicy.ID == id {
			globalIPPolicies = append(globalIPPolicies[:i], globalIPPolicies[i+1:]...)
			break
		}
	}
	err := data.DAL.DeleteIPPolicyByID(id)
	go utils.OperationLog(clientIP, authUser.Username, "Delete IP Policy by ID", strconv.FormatInt(id, 10))
	data.UpdateFirewallLastModified()
	return err
}

// GetIPPolicyByID find item in globalIPPolicies
func GetIPPolicyByID(id int64) (*models.IPPolicy, error) {
	for _, ipPolicy := range globalIPPolicies {
		if ipPolicy.ID == id {
			return ipPolicy, nil
		}
	}
	return nil, errors.New("not found")
}

// GetIPPolicyByIPAddr get IP Policy
func GetIPPolicyByIPAddr(srcIP string) *models.IPPolicy {
	for _, ipPolicy := range globalIPPolicies {
		if ipPolicy.IPAddr == srcIP {
			return ipPolicy
		}
	}
	return nil
}

// RPCLoadIPPolicies for replica nodes get IP Policies
func RPCLoadIPPolicies() []*models.IPPolicy {
	rpcRequest := &models.RPCRequest{
		Action: "get_ip_policies", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCLoadIPPolicies GetResponse", err)
		return nil
	}
	rpcIPPolicies := &models.RPCIPPolicies{}
	if err := json.Unmarshal(resp, rpcIPPolicies); err != nil {
		utils.DebugPrintln("RPCLoadIPPolicies Unmarshal", err)
		return nil
	}
	ipPolicies := rpcIPPolicies.Object
	return ipPolicies
}
