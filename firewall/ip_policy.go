/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2021-01-10 12:16:51
 * @Last Modified: U2, 2021-01-10 12:16:51
 */

package firewall

import (
	"errors"
	"janusec/data"
	"janusec/models"
	"strings"
)

var globalIPPolicies []*models.IPPolicy

// InitIPPolicies load IP Policies to memory
func InitIPPolicies() {
	data.DAL.CreateTableIfNotExistsIPPolicies()
	globalIPPolicies = data.DAL.LoadIPPolicies()
}

// GetIPPolicies return Allow List and Block List
func GetIPPolicies() ([]*models.IPPolicy, error) {
	return globalIPPolicies, nil
}

// UpdateIPPolicy update IP policy
func UpdateIPPolicy(param map[string]interface{}, authUser *models.AuthUser) (*models.IPPolicy, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	ipPolicyI := param["object"].(map[string]interface{})
	id := int64(ipPolicyI["id"].(float64))
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
	return ipPolicy, nil
}

// DeleteIPPolicyByID ...
func DeleteIPPolicyByID(id int64, authUser *models.AuthUser) error {
	if authUser.IsSuperAdmin == false {
		return errors.New("Only super administrators can perform this operation")
	}
	for i, ipPolicy := range globalIPPolicies {
		if ipPolicy.ID == id {
			globalIPPolicies = append(globalIPPolicies[:i], globalIPPolicies[i+1:]...)
			break
		}
	}
	err := data.DAL.DeleteIPPolicyByID(id)
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
