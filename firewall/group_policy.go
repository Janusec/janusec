/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:34:51
 * @Last Modified: U2, 2018-07-14 16:34:51
 */

package firewall

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/usermgmt"
	"github.com/Janusec/janusec/utils"
)

var (
	groupPolicies []*models.GroupPolicy
)

func InitGroupPolicy() {
	var dbGroupPolicies []*models.GroupPolicy
	if data.IsMaster {
		data.DAL.CreateTableIfNotExistsGroupPolicy()
		data.DAL.CreateTableIfNotExistCheckItems()
		existRegexPolicy := data.DAL.ExistsGroupPolicy()
		if existRegexPolicy == false {
			data.DAL.SetIDSeqStartWith("group_policies", 10101)
			curTime := time.Now().Unix()

			groupPolicyID, err := data.DAL.InsertGroupPolicy("Code Leakage", 0, 100, int64(models.ChkPointURLPath), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLPath, models.OperationRegexMatch, "", `(?i)/\.(git|svn)/`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// r.Form get nil when query use % instead for %25, so check it in url query
			groupPolicyID, err = data.DAL.InsertGroupPolicy("SQL Injection with Search", 0, 200, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)%\s+(and|or|procedure)\s+`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// Multiple Sentences SQL Injection  ;\s*(declare|use|drop|create|exec)\s
			groupPolicyID, err = data.DAL.InsertGroupPolicy("SQL Injection with Multiple Sentences", 0, 200, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i);\s*(declare|use|drop|create|exec)\s`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			//  SQL Injection Function
			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Functions", 0, 200, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)(updatexml|extractvalue|ascii|ord|char|chr|count|concat|rand|floor|substr|length|len|user|database|benchmark|analyse)\s?\(`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			//  SQL Injection Case When
			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Case When", 0, 200, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)\(case\s+when\s+[\w\p{L}]+=[\w\p{L}]+\s+then\s+`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Attempt", 0, 200, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)\s+(and|or|procedure)\s+[\w\p{L}]+=[\w\p{L}]+($|--|#)`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Attempt 2", 0, 200, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)\s+(and|or|rlike)\s+(select|case)\s+`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Attempt 3", 0, 200, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)\s+(and|or|rlike)\s+(if|updatexml)\(`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Comment", 0, 200, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)/\*(!|\x00)`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Union SQL Injection", 0, 200, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)union[\s/\*]+select`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Command Injection", 0, 210, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(^|\&\s*|\|\s*)(pwd|ls|ll|whoami|id|net\s+user)$`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Web Shell", 0, 500, int64(models.ChkPointGetPostValue), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)(eval|system|exec|execute|passthru|shell_exec|phpinfo)\(`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			groupPolicyID, err = data.DAL.InsertGroupPolicy("Upload", 0, 510, int64(models.ChkPointUploadFileExt), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointUploadFileExt, models.OperationRegexMatch, "", `(?i)\.(php|jsp|aspx|asp|exe|asa)`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// XSS Tags
			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic XSS Tags", 0, 300, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)<(script|iframe)`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// XSS Functions
			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic XSS Functions", 0, 300, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)(alert|eval|prompt)\(`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// XSS Event
			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic XSS Event", 0, 300, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)(onmouseover|onerror|onload|onclick)\s*=`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// Path Traversal
			groupPolicyID, err = data.DAL.InsertGroupPolicy("Basic Path Traversal", 0, 400, int64(models.ChkPointURLQuery), models.Action_Block_100, true, 0, curTime)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `\.\./\.\./|/etc/passwd$`, groupPolicyID)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

		}
		// Load Policies
		dbGroupPolicies = data.DAL.SelectGroupPolicies()
		for _, dbGroupPolicy := range dbGroupPolicies {
			user, _ := usermgmt.GetAppUserByID(dbGroupPolicy.UserID)
			groupPolicy := &models.GroupPolicy{
				ID:          dbGroupPolicy.ID,
				Description: dbGroupPolicy.Description,
				AppID:       dbGroupPolicy.AppID,
				VulnID:      dbGroupPolicy.VulnID,
				CheckItems:  []*models.CheckItem{},
				HitValue:    dbGroupPolicy.HitValue,
				Action:      dbGroupPolicy.Action,
				IsEnabled:   dbGroupPolicy.IsEnabled,
				User:        user,
				UpdateTime:  dbGroupPolicy.UpdateTime}
			groupPolicies = append(groupPolicies, groupPolicy)
		}
	} else {
		groupPolicies = RPCSelectGroupPolicies()
	}
}

func GetGroupPolicies(app_id int64) ([]*models.GroupPolicy, error) {
	return groupPolicies, nil
}

func GetGroupPolicyByID(id int64) (*models.GroupPolicy, error) {
	for _, groupPolicy := range groupPolicies {
		if groupPolicy.ID == id {
			return groupPolicy, nil
		}
	}
	return nil, errors.New("Not found.")
}

func GetGroupPolicyIndex(id int64) int {
	for i := 0; i < len(groupPolicies); i++ {
		if groupPolicies[i].ID == id {
			return i
		}
	}
	return -1
}

func DeleteGroupPolicyByID(id int64) error {
	groupPolicy, err := GetGroupPolicyByID(id)
	if err != nil {
		return err
	}
	DeleteCheckItemsByGroupPolicy(groupPolicy)
	data.DAL.DeleteGroupPolicyByID(id)
	i := GetGroupPolicyIndex(id)
	groupPolicies = append(groupPolicies[:i], groupPolicies[i+1:]...)
	data.UpdateFirewallLastModified()
	return nil
}

func UpdateGroupPolicy(r *http.Request, userID int64) (*models.GroupPolicy, error) {
	var setGroupPolicyRequest models.RPCSetGroupPolicy
	err := json.NewDecoder(r.Body).Decode(&setGroupPolicyRequest)
	defer r.Body.Close()
	utils.CheckError("UpdateGroupPolicy Decode", err)
	curGroupPolicy := setGroupPolicyRequest.Object
	curGroupPolicy.UpdateTime = time.Now().Unix()
	if curGroupPolicy == nil {
		return nil, errors.New("UpdateGroupPolicy parse body null.")
	}
	checkItems := curGroupPolicy.CheckItems
	curGroupPolicy.HitValue = 0
	for _, checkItem := range checkItems {
		checkItem.GroupPolicy = curGroupPolicy
		curGroupPolicy.HitValue += int64(checkItem.CheckPoint)
	}
	curGroupPolicy.UserID = userID
	curTime := time.Now().Unix()
	if curGroupPolicy.ID == 0 {
		newID, err := data.DAL.InsertGroupPolicy(curGroupPolicy.Description, curGroupPolicy.AppID, curGroupPolicy.VulnID, curGroupPolicy.HitValue, curGroupPolicy.Action, curGroupPolicy.IsEnabled, curGroupPolicy.UserID, curTime)
		utils.CheckError("UpdateGroupPolicy InsertGroupPolicy", err)
		curGroupPolicy.ID = newID
		groupPolicies = append(groupPolicies, curGroupPolicy)
		UpdateCheckItems(curGroupPolicy, checkItems)
	} else {
		groupPolicy, err := GetGroupPolicyByID(curGroupPolicy.ID)
		utils.CheckError("UpdateGroupPolicy GetGroupPolicyByID", err)
		err = data.DAL.UpdateGroupPolicy(curGroupPolicy.Description, curGroupPolicy.AppID, curGroupPolicy.VulnID, curGroupPolicy.HitValue, curGroupPolicy.Action, curGroupPolicy.IsEnabled, curGroupPolicy.UserID, curTime, groupPolicy.ID)
		groupPolicy.Description = curGroupPolicy.Description
		groupPolicy.AppID = curGroupPolicy.AppID
		groupPolicy.VulnID = curGroupPolicy.VulnID
		groupPolicy.HitValue = curGroupPolicy.HitValue
		groupPolicy.Action = curGroupPolicy.Action
		groupPolicy.IsEnabled = curGroupPolicy.IsEnabled
		groupPolicy.UserID = curGroupPolicy.UserID
		groupPolicy.UpdateTime = curTime
		UpdateCheckItems(groupPolicy, checkItems)
	}
	return curGroupPolicy, nil
}

func IsMatchGroupPolicy(hitValueMap *sync.Map, appID int64, value string, checkPoint models.ChkPoint, designatedKey string, needDecode bool) (bool, *models.GroupPolicy) {
	if len(value) == 0 {
		return false, nil
	}
	checkItemsMap, ok := checkPointCheckItemsMap.Load(checkPoint)
	if !ok {
		return false, nil
	}
	//fmt.Println("IsMatchGroupPolicy checkpoint:", check_point)
	checkItems := checkItemsMap.([]*models.CheckItem)
	if needDecode {
		value = UnEscapeRawValue(value)
	}
	for _, checkItem := range checkItems {
		groupPolicy := checkItem.GroupPolicy
		if groupPolicy.IsEnabled == false {
			continue
		}
		if groupPolicy.AppID == 0 || groupPolicy.AppID == appID {
			if len(designatedKey) > 0 && (checkItem.KeyName != designatedKey) {
				continue
			}
			matched := false
			var err error
			switch checkItem.Operation {
			case models.OperationRegexMatch:
				matched, err = regexp.MatchString(checkItem.RegexPolicy, value)
				utils.CheckError("IsMatchGroupPolicy MatchString", err)
			case models.OperationEqualsStringCaseInSensitive:
				if strings.ToLower(checkItem.RegexPolicy) == strings.ToLower(value) {
					matched = true
				}
			case models.OperationGreaterThanInteger:
				policyValue, err := strconv.ParseInt(checkItem.RegexPolicy, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				checkValue, err := strconv.ParseInt(value, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				if checkValue > policyValue {
					matched = true
				}
			case models.OperationEqualsInteger:
				policyValue, err := strconv.ParseInt(checkItem.RegexPolicy, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				checkValue, err := strconv.ParseInt(value, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				if checkValue == policyValue {
					matched = true
				}
			}
			if matched == true {
				hitValueInterface, _ := hitValueMap.LoadOrStore(groupPolicy.ID, int64(0))
				hitValue := hitValueInterface.(int64)
				hitValue += int64(checkItem.CheckPoint)
				if hitValue == groupPolicy.HitValue {
					return matched, groupPolicy
				}
				hitValueMap.Store(groupPolicy.ID, hitValue)
			}
		}
	}
	return false, nil
}

func PreProcessString(value string) string {
	value2 := strings.Replace(value, `'`, ``, -1)
	value2 = strings.Replace(value2, `"`, ``, -1)
	value2 = strings.Replace(value2, `+`, ` `, -1)
	value2 = strings.Replace(value2, `/**/`, ` `, -1)
	return value2
}

func IsMatch(pattern string, str string) (bool, error) {
	return regexp.MatchString(pattern, str)
}

func TestRegex(param map[string]interface{}) (*models.RegexMatch, error) {
	obj := param["object"].(map[string]interface{})
	pattern := obj["pattern"].(string)
	payload := obj["payload"].(string)
	preprocess := obj["preprocess"].(bool)
	if preprocess {
		payload = UnEscapeRawValue(payload)
	}
	matched, err := IsMatch(pattern, payload)
	regexMatch := &models.RegexMatch{Pattern: pattern, Payload: payload, Matched: matched, PreProcess: preprocess}
	return regexMatch, err
}
