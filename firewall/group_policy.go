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

	"../data"
	"../models"
	"../usermgmt"
	"../utils"
)

var (
	group_policies []*models.GroupPolicy
)

func InitGroupPolicy() {
	var db_group_policies []*models.GroupPolicy
	if data.IsMaster {
		data.DAL.CreateTableIfNotExistsGroupPolicy()
		data.DAL.CreateTableIfNotExistCheckItems()
		exist_regex_policy := data.DAL.ExistsGroupPolicy()
		if exist_regex_policy == false {
			data.DAL.SetIDSeqStartWith("group_policies", 10101)
			cur_time := time.Now().Unix()

			group_policy_id, err := data.DAL.InsertGroupPolicy("Code Leakage", 0, 100, int64(models.ChkPoint_URLPath), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLPath, models.Operation_Regex_Match, "", `(?i)/\.(git|svn)/`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// r.Form get nil when query use % instead for %25, so check it in url query
			group_policy_id, err = data.DAL.InsertGroupPolicy("SQL Injection with Search", 0, 200, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i)%\s+(and|or|procedure)\s+`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// Multiple Sentences SQL Injection  ;\s*(declare|use|drop|create|exec)\s
			group_policy_id, err = data.DAL.InsertGroupPolicy("SQL Injection with Multiple Sentences", 0, 200, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i);\s*(declare|use|drop|create|exec)\s`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			//  SQL Injection Function
			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Functions", 0, 200, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i)(updatexml|extractvalue|ascii|ord|char|chr|count|concat|rand|floor|substr|length|len|user|database|benchmark|analyse)\s?\(`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			//  SQL Injection Case When
			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Case When", 0, 200, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i)\(case\s+when\s+[\w\p{L}]+=[\w\p{L}]+\s+then\s+`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Attempt", 0, 200, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(?i)\s+(and|or|procedure)\s+[\w\p{L}]+=[\w\p{L}]+($|--|#)`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Attempt 2", 0, 200, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(?i)\s+(and|or|rlike)\s+(select|case)\s+`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Attempt 3", 0, 200, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(?i)\s+(and|or|rlike)\s+(if|updatexml)\(`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic SQL Injection Comment", 0, 200, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(?i)/\*(!|\x00)`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Union SQL Injection", 0, 200, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(?i)union[\s/\*]+select`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Command Injection", 0, 210, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(^|\&\s*|\|\s*)(pwd|ls|ll|whoami|id|net\s+user)$`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Web Shell", 0, 500, int64(models.ChkPoint_GetPostValue), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_GetPostValue, models.Operation_Regex_Match, "", `(?i)(eval|system|exec|execute|passthru|shell_exec|phpinfo)\(`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			group_policy_id, err = data.DAL.InsertGroupPolicy("Upload", 0, 510, int64(models.ChkPoint_UploadFileExt), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_UploadFileExt, models.Operation_Regex_Match, "", `(?i)\.(php|jsp|aspx|asp|exe|asa)`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// XSS Tags
			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic XSS Tags", 0, 300, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i)<(script|iframe)`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// XSS Functions
			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic XSS Functions", 0, 300, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i)(alert|eval|prompt)\(`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// XSS Event
			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic XSS Event", 0, 300, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `(?i)(onmouseover|onerror|onload|onclick)\s*=`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

			// Path Traversal
			group_policy_id, err = data.DAL.InsertGroupPolicy("Basic Path Traversal", 0, 400, int64(models.ChkPoint_URLQuery), models.Action_Block_100, true, 0, cur_time)
			utils.CheckError("InitGroupPolicy InsertGroupPolicy", err)
			_, err = data.DAL.InsertCheckItem(models.ChkPoint_URLQuery, models.Operation_Regex_Match, "", `\.\./\.\./|/etc/passwd$`, group_policy_id)
			utils.CheckError("InitGroupPolicy InsertCheckItem", err)

		}
		// Load Policies
		db_group_policies = data.DAL.SelectGroupPolicies()
		for _, db_group_policy := range db_group_policies {
			user, _ := usermgmt.GetAppUserByID(db_group_policy.UserID)
			group_policy := &models.GroupPolicy{
				ID:          db_group_policy.ID,
				Description: db_group_policy.Description,
				AppID:       db_group_policy.AppID,
				VulnID:      db_group_policy.VulnID,
				CheckItems:  []*models.CheckItem{},
				HitValue:    db_group_policy.HitValue,
				Action:      db_group_policy.Action,
				IsEnabled:   db_group_policy.IsEnabled,
				User:        user,
				UpdateTime:  db_group_policy.UpdateTime}
			group_policies = append(group_policies, group_policy)
		}
	} else {
		group_policies = RPCSelectGroupPolicies()
	}
}

func GetGroupPolicies(app_id int64) ([]*models.GroupPolicy, error) {
	return group_policies, nil
}

func GetGroupPolicyByID(id int64) (*models.GroupPolicy, error) {
	for _, group_policy := range group_policies {
		if group_policy.ID == id {
			return group_policy, nil
		}
	}
	return nil, errors.New("Not found.")
}

func GetGroupPolicyIndex(id int64) int {
	for i := 0; i < len(group_policies); i++ {
		if group_policies[i].ID == id {
			return i
		}
	}
	return -1
}

func DeleteGroupPolicyByID(id int64) error {
	group_policy, err := GetGroupPolicyByID(id)
	if err != nil {
		return err
	}
	DeleteCheckItemsByGroupPolicy(group_policy)
	data.DAL.DeleteGroupPolicyByID(id)
	i := GetGroupPolicyIndex(id)
	group_policies = append(group_policies[:i], group_policies[i+1:]...)
	data.UpdateFirewallLastModified()
	return nil
}

func UpdateGroupPolicy(r *http.Request, user_id int64) (*models.GroupPolicy, error) {
	var set_group_policy_request models.RPCSetGroupPolicy
	err := json.NewDecoder(r.Body).Decode(&set_group_policy_request)
	defer r.Body.Close()
	utils.CheckError("UpdateGroupPolicy Decode", err)
	//fmt.Println("UpdateGroupPolicy set_group_policy_request:", set_group_policy_request)
	cur_group_policy := set_group_policy_request.Object
	cur_group_policy.UpdateTime = time.Now().Unix()
	if cur_group_policy == nil {
		return nil, errors.New("UpdateGroupPolicy parse body null.")
	}
	check_items := cur_group_policy.CheckItems
	cur_group_policy.HitValue = 0
	for _, check_item := range check_items {
		check_item.GroupPolicy = cur_group_policy
		cur_group_policy.HitValue += int64(check_item.CheckPoint)
	}
	cur_group_policy.UserID = user_id
	cur_time := time.Now().Unix()
	if cur_group_policy.ID == 0 {
		new_id, err := data.DAL.InsertGroupPolicy(cur_group_policy.Description, cur_group_policy.AppID, cur_group_policy.VulnID, cur_group_policy.HitValue, cur_group_policy.Action, cur_group_policy.IsEnabled, cur_group_policy.UserID, cur_time)
		utils.CheckError("UpdateGroupPolicy InsertGroupPolicy", err)
		cur_group_policy.ID = new_id
		group_policies = append(group_policies, cur_group_policy)
		UpdateCheckItems(cur_group_policy, check_items)
	} else {
		group_policy, err := GetGroupPolicyByID(cur_group_policy.ID)
		utils.CheckError("UpdateGroupPolicy GetGroupPolicyByID", err)
		err = data.DAL.UpdateGroupPolicy(cur_group_policy.Description, cur_group_policy.AppID, cur_group_policy.VulnID, cur_group_policy.HitValue, cur_group_policy.Action, cur_group_policy.IsEnabled, cur_group_policy.UserID, cur_time, group_policy.ID)
		group_policy.Description = cur_group_policy.Description
		group_policy.AppID = cur_group_policy.AppID
		group_policy.VulnID = cur_group_policy.VulnID
		group_policy.HitValue = cur_group_policy.HitValue
		group_policy.Action = cur_group_policy.Action
		group_policy.IsEnabled = cur_group_policy.IsEnabled
		group_policy.UserID = cur_group_policy.UserID
		group_policy.UpdateTime = cur_time
		UpdateCheckItems(group_policy, check_items)
	}
	return cur_group_policy, nil
}

func IsMatchGroupPolicy(hit_value_map *sync.Map, app_id int64, value string, check_point models.ChkPoint, designated_key string, need_decode bool) (bool, *models.GroupPolicy) {
	if len(value) == 0 {
		return false, nil
	}
	check_items_map, ok := check_items_map.Load(check_point)
	if !ok {
		return false, nil
	}
	//fmt.Println("IsMatchGroupPolicy checkpoint:", check_point)
	check_items := check_items_map.([]*models.CheckItem)
	if need_decode {
		value = UnEscapeRawValue(value)
	}
	for _, check_item := range check_items {
		group_policy := check_item.GroupPolicy
		if group_policy.IsEnabled == false {
			continue
		}
		if group_policy.AppID == 0 || group_policy.AppID == app_id {
			if len(designated_key) > 0 && (check_item.KeyName != designated_key) {
				continue
			}
			matched := false
			var err error
			switch check_item.Operation {
			case models.Operation_Regex_Match:
				matched, err = regexp.MatchString(check_item.RegexPolicy, value)
				utils.CheckError("IsMatchGroupPolicy MatchString", err)
			case models.Operation_Equals_String_Case_InSensitive:
				if strings.ToLower(check_item.RegexPolicy) == strings.ToLower(value) {
					matched = true
				}
			case models.Operation_GreaterThan_Integer:
				policy_value, err := strconv.ParseInt(check_item.RegexPolicy, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				check_value, err := strconv.ParseInt(value, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				if check_value > policy_value {
					matched = true
				}
			case models.Operation_Equals_Integer:
				policy_value, err := strconv.ParseInt(check_item.RegexPolicy, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				check_value, err := strconv.ParseInt(value, 10, 64)
				utils.CheckError("IsMatchGroupPolicy ParseInt", err)
				if check_value == policy_value {
					matched = true
				}
			}
			if matched == true {
				hit_value_interface, _ := hit_value_map.LoadOrStore(group_policy.ID, int64(0))
				hit_value := hit_value_interface.(int64)
				hit_value += int64(check_item.CheckPoint)
				//fmt.Println("IsMatchGroupPolicy :", check_point, hit_value, group_policy.HitValue)
				if hit_value == group_policy.HitValue {
					return matched, group_policy
				}
				hit_value_map.Store(group_policy.ID, hit_value)
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
	regex_match := &models.RegexMatch{Pattern: pattern, Payload: payload, Matched: matched, PreProcess: preprocess}
	return regex_match, err
}
