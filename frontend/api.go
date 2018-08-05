/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:34
 * @Last Modified: U2, 2018-07-14 16:36:34
 */

package frontend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/Janusec/janusec/backend"
	"github.com/Janusec/janusec/firewall"
	"github.com/Janusec/janusec/settings"
	"github.com/Janusec/janusec/usermgmt"
	"github.com/Janusec/janusec/utils"
)

func ApiHandlerFunc(w http.ResponseWriter, r *http.Request) {
	utils.DebugPrintln("apiHandlerFunc", r.URL.Path)
	bodyBuf, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	decoder := json.NewDecoder(r.Body)
	var param map[string]interface{}
	err := decoder.Decode(&param)
	defer r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	action := param["action"]
	nodeID := param["node_id"]
	var userID int64
	if nodeID != nil {
		// For slave nodes
		if backend.IsValidAuthKey(r, param) == false {
			GenResponseByObject(w, nil, errors.New("AuthKey invalid!"))
			return
		}
	} else {
		// For administrators
		if action != "login" {
			var isLogin bool
			isLogin, userID = usermgmt.IsLogIn(w, r)
			if isLogin == false {
				GenResponseByObject(w, nil, errors.New("Please login!"))
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if utils.Debug {
		dump, err := httputil.DumpRequest(r, true)
		utils.CheckError("ApiHandlerFunc DumpRequest", err)
		fmt.Println(string(dump))
	}
	var obj interface{}
	switch action {
	case "getnodes":
		obj, err = backend.GetNodes()
	case "getnode":
		id := int64(param["id"].(float64))
		obj, err = backend.GetDBNodeByID(id)
	case "updatenode":
		obj, err = backend.UpdateNode(r, param)
	case "getauthuser":
		obj, err = usermgmt.GetAuthUser(w, r)
	case "getapps":
		obj, err = backend.GetApplications()
	case "getapp":
		id := int64(param["id"].(float64))
		obj, err = backend.GetApplicationByID(id)
	case "updateapp":
		obj, err = backend.UpdateApplication(param)
	case "delapp":
		id := int64(param["id"].(float64))
		err = backend.DeleteApplicationByID(id)
	case "getcerts":
		obj, err = backend.GetCertificates()
	case "getcert":
		id := int64(param["id"].(float64))
		obj, err = backend.GetCertificateByID(id)
	case "updatecert":
		obj, err = backend.UpdateCertificate(param)
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
		obj, err = usermgmt.GetAppUsers()
	case "getadmin":
		obj, err = usermgmt.GetAdmin(param)
	case "updateadmin":
		obj, err = usermgmt.UpdateUser(w, r, param)
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
	case "logout":
		obj = nil
		err = usermgmt.Logout(w, r)
	case "log_group_hit":
		obj = nil
		err = firewall.LogGroupHitRequestAPI(r)
	case "getregexlogscount":
		obj, err = firewall.GetGroupLogCount(param)
	case "getregexlog":
		id := int64(param["id"].(float64))
		obj, err = firewall.GetGroupLogByID(id)
	case "getregexlogs":
		obj, err = firewall.GetGroupLogs(param)
	case "getvulnstat":
		obj, err = firewall.GetVulnStat(param)
	case "getweekstat":
		obj, err = firewall.GetWeekStat(param)
	default:
		//fmt.Println("undefined action")
		obj = nil
		err = errors.New("undefined")
	}
	GenResponseByObject(w, obj, err)
}
