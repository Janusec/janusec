/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-03-11 18:49:30
 */

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	discoveryRules []*models.DiscoveryRule
	discoveryCache = cache.New(30*24*time.Hour, 24*time.Hour)
)

func LoadDiscoveryRules() {
	discoveryRules = discoveryRules[0:0]
	if data.IsPrimary {
		discoveryRules, _ = data.DAL.GetAllDiscoveryRules()
	} else {
		// Replica
		rpcDiscoveryRules := RPCGetAllDiscoveryRules()
		if rpcDiscoveryRules != nil {
			discoveryRules = rpcDiscoveryRules
			utils.DebugPrintln("Load Data Discovery Rules OK")
		}
	}
}

func GetDiscoveryRules() []*models.DiscoveryRule {
	return discoveryRules
}

func RPCGetAllDiscoveryRules() []*models.DiscoveryRule {
	rpcRequest := &models.RPCRequest{Action: "get_discovery_rules", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCGetAllDiscoveryRules GetResponse", err)
		return nil
	}
	rpcDiscoveryRules := &models.RPCDiscoveryRules{}
	err = json.Unmarshal(resp, rpcDiscoveryRules)
	if err != nil {
		utils.DebugPrintln("RPCGetAllDiscoveryRules Unmarshal", err)
		return nil
	}
	discoveryRules := rpcDiscoveryRules.Object
	return discoveryRules
}

func UpdateDiscoveryRule(body []byte, clientIP string, authUser *models.AuthUser) (*models.DiscoveryRule, error) {
	var rpcDiscoveryRuleRequest models.APIDiscoveryRuleRequest
	var err error
	if err = json.Unmarshal(body, &rpcDiscoveryRuleRequest); err != nil {
		utils.DebugPrintln("UpdateDiscoveryRule", err)
		return nil, err
	}
	discoveryRule := rpcDiscoveryRuleRequest.Object
	discoveryRule.Editor = authUser.Username
	discoveryRule.UpdateTime = time.Now().Unix()
	if discoveryRule.ID == 0 {
		// new rule
		discoveryRule.ID, err = data.DAL.InsertDiscoveryRule(discoveryRule)
		if err != nil {
			utils.DebugPrintln("UpdateDiscoveryRule", err)
		}
		go utils.OperationLog(clientIP, authUser.Username, "Add Discovery Rule", discoveryRule.FieldName)
		LoadDiscoveryRules()
		data.UpdateDiscoveryLastModified()
		return discoveryRule, err
	} else {
		// update
		err := data.DAL.UpdateDiscoveryRule(discoveryRule)
		if err != nil {
			utils.DebugPrintln("UpdateDiscoveryRule", err)
		}
		go utils.OperationLog(clientIP, authUser.Username, "Update Discovery Rule", discoveryRule.FieldName)
		LoadDiscoveryRules()
		data.UpdateDiscoveryLastModified()
		return discoveryRule, err
	}
}

func DeleteDiscoveryRuleByID(id int64, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin {
		return errors.New("only super administrators can perform this operation")
	}
	for i, discoveryRule := range discoveryRules {
		if discoveryRule.ID == id {
			discoveryRules = append(discoveryRules[:i], discoveryRules[i+1:]...)
			break
		}
	}
	err := data.DAL.DeleteDiscoveryRuleByID(id)
	go utils.OperationLog(clientIP, authUser.Username, "Delete Discovery Rule by ID", strconv.FormatInt(id, 10))
	LoadDiscoveryRules()
	data.UpdateDiscoveryLastModified()
	return err
}

func DataDiscoveryInResponse(value interface{}, r *http.Request) {
	if value == nil {
		return
	}
	valueKind := reflect.TypeOf(value).Kind()
	switch valueKind {
	case reflect.String:
		value2 := value.(string)
		// data discovery
		CheckDiscoveryRules(value2, r)
	case reflect.Map:
		value2 := value.(map[string]interface{})
		for _, subValue := range value2 {
			DataDiscoveryInResponse(subValue, r)
		}
	case reflect.Slice:
		value2 := value.([]interface{})
		for _, subValue := range value2 {
			DataDiscoveryInResponse(subValue, r)
		}
	}
}

func CheckDiscoveryRules(value string, r *http.Request) {
	for _, discoveryRule := range discoveryRules {
		matched, err := regexp.MatchString(discoveryRule.Regex, value)
		if err != nil {
			continue
		}
		if matched {
			// check cache
			// uid example 1: "www.janusec.com"  + "/abc/" + "Phone Number"
			// uid example 2: "www.janusec.com"  +   "/"   + "Phone Number"
			routePath := utils.GetRoutePath(r.URL.Path)
			uid := data.SHA256Hash(r.URL.Host + routePath + discoveryRule.FieldName)
			if _, ok := discoveryCache.Get(uid); !ok {
				// Set cache
				discoveryCache.Set(uid, 1, cache.DefaultExpiration)
				if len(data.NodeSetting.DataDiscoveryAPI) == 0 || len(data.NodeSetting.DataDiscoveryKey) == 0 {
					return
				}
				// report
				// API: POST http://127.0.0.1:8088/api/v1/data-discoveries
				// JSON Body: {"auth_key":"...", "object":{"domain":"www.janusec.com", "path":"/", "field_name":"Phone Number", "anonymized_sample":"13****138***"}}
				// Response: {"status":0, err:null}
				authKey := data.GenAuthKey(data.DataDiscoveryKey)
				anonymizedSample := Anonymize(value)
				body := fmt.Sprintf(`{"auth_key":"%s", "tenant_id":"%s", "object":{"domain":"%s", "path":"%s", "field_name":"%s", "anonymized_sample":"%s"}}`, authKey, data.NodeSetting.DataDiscoveryTenantID, r.URL.Host, routePath, discoveryRule.FieldName, anonymizedSample)
				request, _ := http.NewRequest("POST", data.NodeSetting.DataDiscoveryAPI, bytes.NewReader([]byte(body)))
				request.Header.Set("Content-Type", "application/json")
				resp, err := utils.GetResponse(request)
				if err != nil {
					utils.DebugPrintln("Report Data Discovery", err)
					return
				}
				rpcResp := DataDiscoveryAPIResponse{}
				err = json.Unmarshal(resp, &rpcResp)
				if err != nil {
					utils.DebugPrintln("Report Data Discovery Unmarshal", err)
					return
				}
				if rpcResp.Status != 0 {
					utils.DebugPrintln("Report Data Discovery, Receive Error:", rpcResp.Error)
					return
				}
			}
			//else {
			// discoveryCache.IncrementInt64(uid, 1)
			// fmt.Println("Exist", value, result, expireTime.String())
			//}
			return
		}
	}
}

func Anonymize(value string) string {
	runeValue := []rune(value)
	regex, _ := regexp.Compile(`[\@\-\.\(\)]`)
	for i := 0; i < len(runeValue); i++ {
		// 13800138000 => 138***380**
		if (i/3)%2 != 0 {
			// check whether the char is special char such as @ - ()
			if !regex.MatchString(string(runeValue[i])) {
				runeValue[i] = '*'
			}
		}
	}
	return string(runeValue)
}

type DataDiscoveryAPIResponse struct {
	// Status 0 represent OK, -1 or non 0 represent abnormal
	Status int64  `json:"status"`
	Error  string `json:"err"`
}
