/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:34
 * @Last Modified: U2, 2018-07-14 16:36:34
 */

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"

	"janusec/backend"
	"janusec/data"
	"janusec/firewall"
	"janusec/models"
	"janusec/usermgmt"
	"janusec/utils"
)

//AdminAPIHandlerFunc receive from browser and other nodes
func AdminAPIHandlerFunc(w http.ResponseWriter, r *http.Request) {
	bodyBuf, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	decoder := json.NewDecoder(r.Body)
	var param map[string]interface{}
	err := decoder.Decode(&param)
	if err != nil {
		utils.DebugPrintln("AdminAPIHandlerFunc Decode", err)
	}
	defer r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	action := param["action"]
	var userID int64
	var authUser *models.AuthUser

	// For administrators and OAuth users
	if action != "login" {
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
	switch action {
	case "get_nodes_key":
		obj = data.GetHexEncryptedNodesKey()
		err = nil
	case "get_nodes":
		obj, err = backend.GetNodes()
	case "get_node":
		id := int64(param["id"].(float64))
		obj, err = backend.GetDBNodeByID(id)
	case "del_node":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteNodeByID(id)
	case "get_auth_user":
		obj, err = usermgmt.GetAuthUser(w, r)
	case "get_apps":
		obj, err = backend.GetApplications(authUser)
	case "get_vip_apps":
		obj, err = backend.GetVipApps(authUser)
	case "get_app":
		id := int64(param["id"].(float64))
		obj, err = backend.GetApplicationByID(id)
	case "get_vip_app":
		id := int64(param["id"].(float64))
		obj, err = backend.GetVipAppByID(id)
	case "update_app":
		obj, err = backend.UpdateApplication(param, clientIP, authUser)
	case "update_vip_app":
		obj, err = backend.UpdateVipApp(param, clientIP, authUser)
	case "del_app":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteApplicationByID(id, clientIP, authUser)
	case "del_vip_app":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteVipAppByID(id, clientIP, authUser)
	case "get_certs":
		obj, err = backend.GetCertificates(authUser)
	case "get_cert":
		id := int64(param["id"].(float64))
		obj, err = backend.GetCertificateByID(id, authUser)
	case "update_cert":
		obj, err = backend.UpdateCertificate(param, clientIP, authUser)
	case "del_cert":
		id := int64(param["id"].(float64))
		obj = nil
		err = backend.DeleteCertificateByID(id, clientIP, authUser)
	case "self_sign_cert":
		obj, err = utils.GenerateRSACertificate(param)
	case "get_domains":
		obj = backend.Domains
		err = nil
	case "get_app_users":
		obj, err = usermgmt.GetAppUsers(authUser)
	case "get_app_user":
		obj, err = usermgmt.GetAdmin(param)
	case "update_app_user":
		obj, err = usermgmt.UpdateUser(w, r, param, clientIP, authUser)
	case "del_app_user":
		id := int64(param["id"].(float64))
		obj = nil
		err = usermgmt.DeleteUser(id, clientIP, authUser)
	case "get_cc_policy":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetCCPolicyRespByAppID(id)
	case "del_cc_policy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteCCPolicyByAppID(id, clientIP, authUser, true)
	case "update_cc_policy":
		obj = nil
		err = firewall.UpdateCCPolicy(param, clientIP, authUser)
	case "get_group_policies":
		appID := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicies(appID)
	case "get_group_policy":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicyByID(id)
	case "update_group_policy":
		obj, err = firewall.UpdateGroupPolicy(r, userID, clientIP, authUser)
	case "get_ip_policies":
		obj, err = firewall.GetIPPolicies()
	case "update_ip_policy":
		obj, err = firewall.UpdateIPPolicy(param, clientIP, authUser)
	case "del_ip_policy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteIPPolicyByID(id, clientIP, authUser)
	case "del_group_policy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteGroupPolicyByID(id, clientIP, authUser)
	case "test_regex":
		obj, err = firewall.TestRegex(param)
	case "get_vuln_types":
		obj, err = firewall.GetVulnTypes()
	case "login":
		obj, err = usermgmt.Login(w, r, param, clientIP)
	case "logout":
		obj = nil
		err = usermgmt.Logout(w, r)
	case "get_regex_logs_count":
		obj, err = firewall.GetGroupLogCount(param)
	case "get_regex_logs":
		obj, err = firewall.GetGroupLogs(param)
	case "get_regex_log":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupLogByID(id)
	case "get_cc_logs_count":
		obj, err = firewall.GetCCLogCount(param)
	case "get_cc_logs":
		obj, err = firewall.GetCCLogs(param)
	case "get_cc_log":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetCCLogByID(id)
	case "get_vuln_stat":
		obj, err = firewall.GetVulnStat(param)
	case "get_week_stat":
		obj, err = firewall.GetWeekStat(param)
	case "get_access_stat":
		obj, err = GetAccessStat(param)
	case "get_referer_hosts":
		obj, err = GetRefererHosts(param)
	case "get_referer_urls":
		obj, err = GetRefererURLs(param)
	case "get_pop_contents":
		obj, err = GetTodayPopularContent(param)
	case "get_gateway_health":
		obj, err = GetGatewayHealth()
	case "get_primary_setting":
		obj, err = data.GetPrimarySetting(authUser)
	case "update_primary_setting":
		obj, err = data.UpdatePrimarySetting(r, param, clientIP, authUser)
	case "get_wxwork_config":
		obj = data.GetWxworkConfig()
		err = nil
	case "update_wxwork_config":
		obj, err = data.UpdateWxworkConfig(param, clientIP, authUser)
	case "get_dingtalk_config":
		obj = data.GetDingtalkConfig()
		err = nil
	case "update_dingtalk_config":
		obj, err = data.UpdateDingtalkConfig(param, clientIP, authUser)
	case "get_feishu_config":
		obj = data.GetFeishuConfig()
		err = nil
	case "update_feishu_config":
		obj, err = data.UpdateFeishuConfig(param, clientIP, authUser)
	case "get_lark_config":
		obj = data.GetLarkConfig()
		err = nil
	case "update_lark_config":
		obj, err = data.UpdateLarkConfig(param, clientIP, authUser)
	case "get_ldap_config":
		obj = data.GetLDAPConfig()
		err = nil
	case "update_ldap_config":
		obj, err = data.UpdateLDAPConfig(param, clientIP, authUser)
	case "get_cas2_config":
		obj = data.GetCAS2Config()
		err = nil
	case "update_cas2_config":
		obj, err = data.UpdateCAS2Config(param, clientIP, authUser)
	case "get_license":
		obj, err = nil, nil
	case "test_smtp":
		obj, err = nil, TestSMTP(r)
	default:
		//fmt.Println("undefined action")
		obj = nil
		err = errors.New("undefined")
	}
	GenResponseByObject(w, obj, err)
}

//ReplicaAPIHandlerFunc receive from browser and other nodes
func ReplicaAPIHandlerFunc(w http.ResponseWriter, r *http.Request) {
	bodyBuf, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	decoder := json.NewDecoder(r.Body)
	var param map[string]interface{}
	err := decoder.Decode(&param)
	if err != nil {
		utils.DebugPrintln("ReplicaAPIHandlerFunc Decode", err)
	}
	defer r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	action := param["action"]
	authKey := param["auth_key"]
	var authUser *models.AuthUser
	if authKey != nil {
		// For replica nodes
		if !backend.IsValidAuthKey(r, param) {
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
		appID := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicies(appID)
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
		id := int64(param["id"].(float64))
		obj, err = usermgmt.UpdateTOTPVerified(id)
	case "update_access_stat":
		obj = nil
		err = RPCIncAccessStat(r)
	case "update_referer_stat":
		obj = nil
		//mapReferer := param["object"]
		err = RPCUpdateRefererStat(r)
	default:
		//fmt.Println("undefined action:", action)
		utils.DebugPrintln("undefined action:", action)
		obj = nil
		err = errors.New("undefined")
	}
	GenResponseByObject(w, obj, err)
}

// GenResponseByObject generate response
func GenResponseByObject(w http.ResponseWriter, object interface{}, err error) {
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
