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
	"janusec/settings"
	"janusec/usermgmt"
	"janusec/utils"
)

//APIHandlerFunc receive from browser and other nodes
func APIHandlerFunc(w http.ResponseWriter, r *http.Request) {
	bodyBuf, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	decoder := json.NewDecoder(r.Body)
	var param map[string]interface{}
	err := decoder.Decode(&param)
	defer r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	action := param["action"]
	authKey := param["auth_key"]
	var userID int64
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
	} else {
		// For administrators and OAuth users
		if action != "login" {
			authUser, err = usermgmt.GetAuthUser(w, r)
			if authUser == nil {
				GenResponseByObject(w, nil, err)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if utils.Debug {
		dump, err := httputil.DumpRequest(r, true)
		utils.CheckError("APIHandlerFunc DumpRequest", err)
		fmt.Println(string(dump))
	}
	var obj interface{}
	switch action {
	case "getnodeskey":
		obj = data.GetHexEncryptedNodesKey()
		err = nil
	case "getnodes":
		obj, err = backend.GetNodes()
	case "getnode":
		id := int64(param["id"].(float64))
		obj, err = backend.GetDBNodeByID(id)
	case "delnode":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteNodeByID(id)
	case "getauthuser":
		obj, err = usermgmt.GetAuthUser(w, r)
	case "getapps":
		obj, err = backend.GetApplications(authUser)
	case "getapp":
		id := int64(param["id"].(float64))
		obj, err = backend.GetApplicationByID(id)
	case "updateapp":
		obj, err = backend.UpdateApplication(param)
	case "delapp":
		obj = nil
		id := int64(param["id"].(float64))
		err = backend.DeleteApplicationByID(id)
	case "getcerts":
		obj, err = backend.GetCertificates(authUser)
	case "getcert":
		id := int64(param["id"].(float64))
		obj, err = backend.GetCertificateByID(id, authUser)
	case "updatecert":
		obj, err = backend.UpdateCertificate(param, authUser)
	case "delcert":
		id := int64(param["id"].(float64))
		obj = nil
		err = backend.DeleteCertificateByID(id)
	case "selfsigncert":
		obj, err = utils.GenerateRSACertificate(param)
	case "getdomains":
		obj = backend.Domains
		err = nil
	case "getadmins":
		obj, err = usermgmt.GetAppUsers(authUser)
	case "getadmin":
		obj, err = usermgmt.GetAdmin(param)
	case "updateadmin":
		obj, err = usermgmt.UpdateUser(w, r, param, authUser)
	case "deladmin":
		id := int64(param["id"].(float64))
		obj = nil
		err = usermgmt.DeleteUser(id)
	case "getccpolicies":
		obj, err = firewall.GetCCPolicies()
	case "getccpolicy":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetCCPolicyRespByAppID(id)
	case "delccpolicy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteCCPolicyByAppID(id)
	case "updateccpolicy":
		obj = nil
		err = firewall.UpdateCCPolicy(param)
	case "getgrouppolicies":
		app_id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicies(app_id)
	case "getgrouppolicy":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupPolicyByID(id)
	case "updategrouppolicy":
		obj, err = firewall.UpdateGroupPolicy(r, userID)
	case "delgrouppolicy":
		id := int64(param["id"].(float64))
		obj = nil
		err = firewall.DeleteGroupPolicyByID(id)
	case "testregex":
		obj, err = firewall.TestRegex(param)
	case "getvulntypes":
		obj, err = firewall.GetVulnTypes()
	case "getsettings":
		obj, err = settings.GetSettings()
	case "login":
		obj, err = usermgmt.Login(w, r, param)
	case "getoauthconf":
		obj, err = usermgmt.GetOAuthConfig()
	case "logout":
		obj = nil
		err = usermgmt.Logout(w, r)
	case "log_group_hit":
		obj = nil
		err = firewall.LogGroupHitRequestAPI(r)
	case "log_cc":
		obj = nil
		err = firewall.LogCCRequestAPI(r)
	case "getregexlogscount":
		obj, err = firewall.GetGroupLogCount(param)
	case "getcclogscount":
		obj, err = firewall.GetCCLogCount(param)
	case "getregexlog":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupLogByID(id)
	case "getcclog":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetCCLogByID(id)
	case "getregexlogs":
		obj, err = firewall.GetGroupLogs(param)
	case "getcclogs":
		obj, err = firewall.GetCCLogs(param)
	case "getvulnstat":
		obj, err = firewall.GetVulnStat(param)
	case "getweekstat":
		obj, err = firewall.GetWeekStat(param)
	case "gettotpkey":
		// used for authenticator launched by replica nodes
		obj, err = usermgmt.GetOrInsertTOTPItem(param)
	case "updatetotp":
		id := int64(param["id"].(float64))
		obj, err = usermgmt.UpdateTOTPVerified(id)
	case "getaccessstat":
		obj, err = GetAccessStat(param)
	case "getpopcontents":
		obj, err = GetTodayPopularContent(param)
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

func GenResponseByObject(w http.ResponseWriter, object interface{}, err error) {
	resp := new(models.RPCResponse)
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
