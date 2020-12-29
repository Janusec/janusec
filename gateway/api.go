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
		utils.CheckError("AdminAPIHandlerFunc DumpRequest", err)
		fmt.Println(string(dump))
	}
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
		obj, err = backend.UpdateApplication(param)
	case "update_vip_app":
		obj, err = backend.UpdateVipApp(param, authUser)
	case "del_app":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteApplicationByID(id, authUser)
	case "del_vip_app":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteVipAppByID(id)
	case "get_certs":
		obj, err = backend.GetCertificates(authUser)
	case "get_cert":
		id := int64(param["id"].(float64))
		obj, err = backend.GetCertificateByID(id, authUser)
	case "update_cert":
		obj, err = backend.UpdateCertificate(param, authUser)
	case "del_cert":
		id := int64(param["id"].(float64))
		obj = nil
		err = backend.DeleteCertificateByID(id)
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
		obj, err = usermgmt.UpdateUser(w, r, param, authUser)
	case "del_app_user":
		id := int64(param["id"].(float64))
		obj = nil
		err = usermgmt.DeleteUser(id, authUser)
	case "get_cc_policy":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetCCPolicyRespByAppID(id)
	case "del_cc_policy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteCCPolicyByAppID(id, authUser, true)
	case "update_cc_policy":
		obj = nil
		err = firewall.UpdateCCPolicy(param, authUser)
	case "get_group_policies":
		appID := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicies(appID)
	case "get_group_policy":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicyByID(id)
	case "update_group_policy":
		obj, err = firewall.UpdateGroupPolicy(r, userID, authUser)
	case "del_group_policy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteGroupPolicyByID(id, authUser)
	case "test_regex":
		obj, err = firewall.TestRegex(param)
	case "get_vuln_types":
		obj, err = firewall.GetVulnTypes()
	case "login":
		obj, err = usermgmt.Login(w, r, param)
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
	case "get_pop_contents":
		obj, err = GetTodayPopularContent(param)
	case "get_gateway_health":
		obj, err = GetGatewayHealth()
	case "get_global_settings":
		obj, err = data.GetGlobalSettings(authUser)
	case "update_global_settings":
		obj, err = data.UpdateGlobalSettings(param, authUser)
	case "get_license":
		obj, err = nil, nil
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
	defer r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	action := param["action"]
	authKey := param["auth_key"]
	var authUser *models.AuthUser
	if authKey != nil {
		// For replica nodes
		if backend.IsValidAuthKey(r, param) == false {
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
		utils.CheckError("ReplicaAPIHandlerFunc DumpRequest", err)
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
	case "get_vuln_types":
		obj, err = firewall.GetVulnTypes()
	case "get_settings":
		obj, err = data.GetSettings()
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
	case "inc_stat":
		obj = nil
		err = ReplicaIncAccessStat(r)
	default:
		//fmt.Println("undefined action")
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
