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
	"strings"
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
func UpdateIPPolicy(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.IPPolicy, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	ipPolicyI := param["object"].(map[string]interface{})
	id, _ := strconv.ParseInt(ipPolicyI["id"].(string), 10, 64)
	ipAddr := ipPolicyI["ip_addr"].(string)
	ipAddr = strings.Trim(ipAddr, " ")
	isAllow := ipPolicyI["is_allow"].(bool)
	applyToWAF := ipPolicyI["apply_to_waf"].(bool)
	applyToCC := ipPolicyI["apply_to_cc"].(bool)
	if id == 0 {
		// New IP
		newID := data.DAL.InsertIPPolicy(ipAddr, isAllow, applyToWAF, applyToCC)
		ipPolicy := &models.IPPolicy{
			ID:         newID,
			IPAddr:     ipAddr,
			IsAllow:    isAllow,
			ApplyToWAF: applyToWAF,
			ApplyToCC:  applyToCC,
		}
		globalIPPolicies = append(globalIPPolicies, ipPolicy)
		go utils.OperationLog(clientIP, authUser.Username, "Add IP Policy", ipAddr)
		data.UpdateFirewallLastModified()
		return ipPolicy, nil
	}
	// Update
	ipPolicy, err := GetIPPolicyByID(id)
	if err != nil {
		return nil, err
	}
	ipPolicy.IPAddr = ipAddr
	ipPolicy.IsAllow = isAllow
	ipPolicy.ApplyToWAF = applyToWAF
	ipPolicy.ApplyToCC = applyToCC
	err = data.DAL.UpdateIPPolicy(id, ipAddr, isAllow, applyToWAF, applyToCC)
	if err != nil {
		return nil, err
	}
	go utils.OperationLog(clientIP, authUser.Username, "Update IP Policy", ipAddr)
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
