/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:34
 * @Last Modified: U2, 2018-07-14 16:36:34
 */

package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"janusec/backend"
	"janusec/data"
	"janusec/firewall"
	"janusec/models"
	"janusec/usermgmt"
	"janusec/utils"
)

// AdminAPIHandlerFunc receive from browser and other nodes
func AdminAPIHandlerFunc(w http.ResponseWriter, r *http.Request) {
	var err error
	bodyBuf, _ := io.ReadAll(r.Body)

	var apiRequest models.APIRequest
	if err := json.Unmarshal(bodyBuf, &apiRequest); err != nil {
		utils.DebugPrintln("API", err)
		GenResponseByObject(w, nil, err)
		return
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
	defer r.Body.Close()
	/*
		decoder := json.NewDecoder(r.Body)
		var param map[string]interface{}
		err := decoder.Decode(&param)
		if err != nil {
			utils.DebugPrintln("AdminAPIHandlerFunc Decode", err)
		}
		defer r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
	*/
	//var userID int64
	var authUser *models.AuthUser

	if len(apiRequest.AuthKey) > 0 {
		// Request come from external control panels, not from UI
		if !IsValidAPIAuthKey(apiRequest.AuthKey) {
			GenResponseByObject(w, nil, errors.New("invalid auth_key"))
			return
		}
		// for privilege check
		authUser = &models.AuthUser{
			UserID:        0,
			Username:      "ExternalAPI",
			Logged:        true,
			IsSuperAdmin:  true,
			IsCertAdmin:   true,
			IsAppAdmin:    true,
			NeedModifyPWD: false,
		}
	} else if (apiRequest.Action != "login") && (apiRequest.Action != "verify_totp") {
		// Request come from UI, administrators and OAuth users
		authUser, err = usermgmt.GetAuthUser(w, r)
		if authUser == nil {
			GenResponseByObject(w, nil, err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if utils.Debug {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			utils.DebugPrintln("AdminAPIHandlerFunc DumpRequest", err)
		}
		fmt.Println(string(dump))
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	var obj interface{}
	switch apiRequest.Action {
	case "get_api_key":
		obj = data.GetHexAPIKey()
		err = nil
	case "get_nodes_key":
		obj = data.GetHexEncryptedNodesKey()
		err = nil
	case "get_nodes":
		obj, err = backend.GetNodes()
	case "get_node":
		obj, err = backend.GetDBNodeByID(apiRequest.ObjectID)
	case "del_node":
		obj = nil
		err = backend.DeleteNodeByID(apiRequest.ObjectID)
	case "get_auth_user":
		obj, err = usermgmt.GetAuthUser(w, r)
	case "get_apps":
		obj, err = backend.GetApplications(authUser)
	case "get_vip_apps":
		obj, err = backend.GetVipApps(authUser)
	case "get_app":
		obj, err = backend.GetApplicationByID(apiRequest.ObjectID)
	case "get_vip_app":
		obj, err = backend.GetVipAppByID(apiRequest.ObjectID)
	case "update_app":
		obj, err = backend.UpdateApplication(bodyBuf, clientIP, authUser)
	case "update_vip_app":
		obj, err = backend.UpdateVipApp(bodyBuf, clientIP, authUser)
	case "del_app":
		obj = nil
		err = backend.DeleteApplicationByID(apiRequest.ObjectID, clientIP, authUser)
	case "del_vip_app":
		obj = nil
		err = backend.DeleteVipAppByID(apiRequest.ObjectID, clientIP, authUser)
	case "get_certs":
		obj, err = backend.GetCertificates(authUser)
	case "get_cert":
		obj, err = backend.GetCertificateByID(apiRequest.ObjectID, authUser)
	case "update_cert":
		obj, err = backend.UpdateCertificate(bodyBuf, clientIP, authUser)
	case "del_cert":
		obj = nil
		err = backend.DeleteCertificateByID(apiRequest.ObjectID, clientIP, authUser)
	case "self_sign_cert":
		obj, err = utils.GenerateRSACertificate(bodyBuf)
	case "get_domains":
		obj = backend.Domains
		err = nil
	case "get_app_users":
		obj, err = usermgmt.GetAppUsers(authUser)
	case "get_app_user":
		obj, err = usermgmt.GetAppUserByID(apiRequest.ObjectID)
	case "update_app_user":
		obj, err = usermgmt.UpdateAppUser(w, r, bodyBuf, clientIP, authUser)
	case "del_app_user":
		obj = nil
		err = usermgmt.DeleteUser(apiRequest.ObjectID, clientIP, authUser)
	case "get_cc_policy":
		obj = firewall.GetCCPolicyByAppID(apiRequest.ObjectID)
		err = nil
	case "del_cc_policy":
		obj = nil
		err = firewall.DeleteCCPolicyByAppID(apiRequest.ObjectID, clientIP, authUser, true)
	case "update_cc_policy":
		obj = nil
		err = firewall.UpdateCCPolicy(bodyBuf, clientIP, authUser)
	case "get_group_policies":
		obj, err = firewall.GetGroupPolicies()
	case "get_group_policy":
		obj, err = firewall.GetGroupPolicyByID(apiRequest.ObjectID)
	case "update_group_policy":
		obj, err = firewall.UpdateGroupPolicy(r, clientIP, authUser)
	case "get_ip_policies":
		obj, err = firewall.GetIPPolicies()
	case "update_ip_policy":
		obj, err = firewall.UpdateIPPolicy(bodyBuf, clientIP, authUser)
	case "del_ip_policy":
		obj = nil
		err = firewall.DeleteIPPolicyByID(apiRequest.ObjectID, clientIP, authUser)
	case "del_group_policy":
		obj = nil
		err = firewall.DeleteGroupPolicyByID(apiRequest.ObjectID, clientIP, authUser)
	case "test_regex":
		obj, err = firewall.TestRegex(bodyBuf)
	case "get_vuln_types":
		obj, err = firewall.GetVulnTypes()
	case "login":
		obj, err = usermgmt.Login(w, r, bodyBuf, clientIP)
	case "logout":
		obj = nil
		err = usermgmt.Logout(w, r)
	case "get_regex_logs_count":
		obj, err = firewall.GetGroupLogCount(bodyBuf)
	case "get_regex_logs":
		obj, err = firewall.GetGroupLogs(bodyBuf)
	case "get_regex_log":
		obj, err = firewall.GetGroupLogByID(apiRequest.ObjectID)
	case "get_cc_logs_count":
		obj, err = firewall.GetCCLogCount(bodyBuf)
	case "get_cc_logs":
		obj, err = firewall.GetCCLogs(bodyBuf)
	case "get_cc_log":
		obj, err = firewall.GetCCLogByID(apiRequest.ObjectID)
	case "get_vuln_stat":
		obj, err = firewall.GetVulnStat(bodyBuf)
	case "get_week_stat":
		obj, err = firewall.GetWeekStat(bodyBuf)
	case "get_access_stat":
		obj, err = GetAccessStat(bodyBuf)
	case "get_referer_hosts":
		obj, err = GetRefererHosts(bodyBuf)
	case "get_referer_urls":
		obj, err = GetRefererURLs(bodyBuf)
	case "get_pop_contents":
		obj, err = GetTodayPopularContent(bodyBuf)
	case "get_gateway_health":
		obj, err = GetGatewayHealth()
	case "get_primary_setting":
		obj, err = data.GetPrimarySetting(authUser)
	case "update_primary_setting":
		obj, err = data.UpdatePrimarySetting(r, bodyBuf, clientIP, authUser)
	case "get_wxwork_config":
		obj = data.GetWxworkConfig()
		err = nil
	case "update_wxwork_config":
		obj, err = data.UpdateWxworkConfig(bodyBuf, clientIP, authUser)
	case "get_dingtalk_config":
		obj = data.GetDingtalkConfig()
		err = nil
	case "update_dingtalk_config":
		obj, err = data.UpdateDingtalkConfig(bodyBuf, clientIP, authUser)
	case "get_feishu_config":
		obj = data.GetFeishuConfig()
		err = nil
	case "update_feishu_config":
		obj, err = data.UpdateFeishuConfig(bodyBuf, clientIP, authUser)
	case "get_lark_config":
		obj = data.GetLarkConfig()
		err = nil
	case "update_lark_config":
		obj, err = data.UpdateLarkConfig(bodyBuf, clientIP, authUser)
	case "get_ldap_config":
		obj = data.GetLDAPConfig()
		err = nil
	case "update_ldap_config":
		obj, err = data.UpdateLDAPConfig(bodyBuf, clientIP, authUser)
	case "get_cas2_config":
		obj = data.GetCAS2Config()
		err = nil
	case "update_cas2_config":
		obj, err = data.UpdateCAS2Config(bodyBuf, clientIP, authUser)
	case "get_license":
		obj, err = nil, nil
	case "test_smtp":
		obj, err = nil, TestSMTP(r)
	case "verify_totp":
		obj, err = nil, usermgmt.VerifyTOTP(bodyBuf)
	case "get_discovery_rules":
		obj = firewall.GetDiscoveryRules()
		err = nil
	case "update_discovery_rule":
		obj, err = firewall.UpdateDiscoveryRule(bodyBuf, clientIP, authUser)
	case "del_discovery_rule":
		obj = nil
		err = firewall.DeleteDiscoveryRuleByID(apiRequest.ObjectID, clientIP, authUser)
	default:
		//fmt.Println("undefined action")
		obj = nil
		err = errors.New("undefined")
	}
	GenResponseByObject(w, obj, err)
}

// ReplicaAPIHandlerFunc receive from other nodes
func ReplicaAPIHandlerFunc(w http.ResponseWriter, r *http.Request) {
	bodyBuf, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
	decoder := json.NewDecoder(r.Body)
	var param map[string]interface{}
	err := decoder.Decode(&param)
	if err != nil {
		utils.DebugPrintln("ReplicaAPIHandlerFunc Decode", err)
	}
	defer r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
	action := param["action"]
	authKey := param["auth_key"]
	var authUser *models.AuthUser
	if authKey != nil {
		// For replica nodes
		if !backend.IsValidAuthKeyFromReplicaNode(r, param) {
			GenResponseByObject(w, nil, errors.New("authkey invalid"))
			return
		}
		// for privilege check and sync data from replica nodes
		authUser = &models.AuthUser{
			UserID:        0,
			Username:      "node",
			Logged:        true,
			IsSuperAdmin:  true,
			IsCertAdmin:   true,
			IsAppAdmin:    true,
			NeedModifyPWD: false,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if utils.Debug {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			utils.DebugPrintln("ReplicaAPIHandlerFunc DumpRequest", err)
		}
		fmt.Println(string(dump))
	}
	var obj interface{}
	switch action {
	case "get_apps":
		obj, err = backend.GetApplications(authUser)
	case "get_vip_apps":
		obj, err = backend.GetVipApps(authUser)
	case "get_certs":
		obj, err = backend.GetCertificates(authUser)
	case "get_domains":
		obj = backend.Domains
		err = nil
	case "get_cc_policies":
		obj, err = firewall.GetCCPolicies()
	case "get_group_policies":
		obj, err = firewall.GetGroupPolicies()
	case "get_ip_policies":
		obj, err = firewall.GetIPPolicies()
	case "get_vuln_types":
		obj, err = firewall.GetVulnTypes()
	case "get_node_setting":
		obj, err = data.GetNodeSetting(), nil
	case "get_oauth_conf":
		obj, err = usermgmt.GetOAuthConfig()
	case "log_group_hit":
		obj = nil
		err = firewall.LogGroupHitRequestAPI(r)
	case "log_cc":
		obj = nil
		err = firewall.LogCCRequestAPI(r)
	case "get_totp_key":
		// used for authenticator launched by replica nodes
		obj, err = usermgmt.GetOrInsertTOTPItem(param)
	case "update_totp":
		id, _ := strconv.ParseInt(param["id"].(string), 10, 64)
		obj, err = usermgmt.UpdateTOTPVerified(id)
	case "update_access_stat":
		obj = nil
		err = RPCIncAccessStat(r)
	case "update_referer_stat":
		obj = nil
		//mapReferer := param["object"]
		err = RPCUpdateRefererStat(r)
	case "get_discovery_rules":
		obj = firewall.GetDiscoveryRules()
		err = nil
	default:
		//fmt.Println("undefined action:", action)
		utils.DebugPrintln("undefined action:", action)
		obj = nil
		err = errors.New("undefined")
	}
	GenResponseByObject(w, obj, err)
}

// GenResponseByObject generate response
func GenResponseByObject(w http.ResponseWriter, object any, err error) {
	resp := &models.RPCResponse{}
	if err == nil {
		resp.Error = nil
	} else {
		errStr := err.Error()
		resp.Error = &errStr
	}
	resp.Object = object
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		utils.DebugPrintln("GenResponseByObject Encode error", err)
	}
}

// IsValidAPIAuthKey check whether the request is from legal external control panels
func IsValidAPIAuthKey(authKey string) bool {
	authBytes, err := hex.DecodeString(authKey)
	if err != nil {
		return false
	}
	decryptedAuthBytes, err := data.DecryptWithKey(authBytes, data.APIKey)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey DecryptWithKey", err)
		return false
	}
	// check timestamp
	authTime := &models.AuthTime{}
	err = json.Unmarshal(decryptedAuthBytes, authTime)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey Unmarshal", err)
		return false
	}
	curTime := time.Now().Unix()
	secondsDiff := math.Abs(float64(curTime - authTime.CurTime))
	return secondsDiff <= 1800.0
}
