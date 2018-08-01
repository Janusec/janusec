/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:33:22
 * @Last Modified: U2, 2018-07-14 16:33:22
 */

package firewall

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
)

var (
	cc_policies_list []*models.CCPolicy
	cc_policies      sync.Map //map[int64]*models.CCPolicy // key: app_id==0  Global Policy
	cc_counts        sync.Map //map[int64]*(map[string]*models.ClientStat) // app_id, client_id, ClientStat
	cc_tickers       sync.Map //map[int64]*time.Ticker
)

func ClearCCStatByClientID(policy_app_id int64, client_id string) {
	if cc_count, ok := cc_counts.Load(policy_app_id); ok {
		app_cc_count := cc_count.(*sync.Map)
		app_cc_count.Delete(client_id)
	}
}

func CCAttackTick(app_id int64) {
	if app_cc_ticker, ok := cc_tickers.Load(app_id); ok {
		cc_ticker := app_cc_ticker.(*time.Ticker)
		cc_ticker.Stop()
	}
	cc_policy_map, _ := cc_policies.Load(app_id)
	cc_policy := cc_policy_map.(*models.CCPolicy)
	cc_ticker := time.NewTicker(cc_policy.IntervalSeconds * time.Second)

	cc_tickers.Store(app_id, cc_ticker)
	for range cc_ticker.C {
		cc_count, _ := cc_counts.LoadOrStore(app_id, &sync.Map{})
		//fmt.Println("CCAttackTick AppID=", app_id, time.Now())
		app_cc_count := cc_count.(*sync.Map)
		app_cc_count.Range(func(key, value interface{}) bool {
			client_id := key.(string)
			stat := value.(*models.ClientStat)
			//fmt.Println("CCAttackTick:", app_id, client_id, stat)
			if stat.IsBlackIP == true {
				stat.RemainSeconds -= cc_policy.IntervalSeconds
				if stat.RemainSeconds <= 0 {
					app_cc_count.Delete(client_id)
				}
			} else if stat.Count >= cc_policy.MaxCount {
				stat.Count = 0
				stat.IsBlackIP = true
				stat.RemainSeconds = cc_policy.BlockSeconds
			} else {
				app_cc_count.Delete(client_id)
			}
			return true
		})
	}
}

func GetCCPolicyByAppID(app_id int64) *models.CCPolicy {
	if cc_policy, ok := cc_policies.Load(app_id); ok {
		return cc_policy.(*models.CCPolicy)
	}
	cc_policy, _ := cc_policies.Load(int64(0))
	return cc_policy.(*models.CCPolicy)
}

func GetCCPolicies() ([]*models.CCPolicy, error) {
	return cc_policies_list, nil
}

func GetCCPolicyRespByAppID(app_id int64) (*models.CCPolicy, error) {
	cc_policy := GetCCPolicyByAppID(app_id)
	return cc_policy, nil
}

func IsCCAttack(r *http.Request, app_id int64, src_ip string) (bool, *models.CCPolicy, string) {
	cc_policy := GetCCPolicyByAppID(app_id)
	if cc_policy.IsEnabled == false {
		return false, nil, ""
	}
	if cc_policy.AppID == 0 {
		app_id = 0 // Important: stat within general policy
	}
	cc_count, _ := cc_counts.LoadOrStore(app_id, &sync.Map{})
	app_cc_count := cc_count.(*sync.Map)
	pre_hash_content := src_ip
	if cc_policy.StatByURL == true {
		pre_hash_content += r.URL.Path
	}
	if cc_policy.StatByUserAgent == true {
		ua := r.Header.Get("User-Agent")
		pre_hash_content += ua
	}
	if cc_policy.StatByCookie == true {
		cookie := r.Header.Get("Cookie")
		pre_hash_content += cookie
	}
	client_id := data.SHA256Hash(pre_hash_content)
	client_id_stat, _ := app_cc_count.LoadOrStore(client_id, &models.ClientStat{Count: 0, IsBlackIP: false, RemainSeconds: 0})
	client_stat := client_id_stat.(*models.ClientStat)
	if client_stat.IsBlackIP == true {
		return true, cc_policy, client_id
	}
	client_stat.Count += 1
	//fmt.Println("IsCCAttack:", r.URL.Path, client_id, client_stat.Count, client_stat.IsBlackIP, client_stat.RemainSeconds)
	return false, nil, ""
}

func InitCCPolicy() {
	//var cc_policies_list []*models.CCPolicy
	if data.IsMaster {
		data.DAL.CreateTableIfNotExistsCCPolicy()
		exist_cc_policy := data.DAL.ExistsCCPolicy()
		if exist_cc_policy == false {
			data.DAL.InsertCCPolicy(0, 10, 60, 300, models.Action_Block_100, true, true, false, true)
		}
		cc_policies_list = data.DAL.SelectCCPolicies()
	} else {
		cc_policies_list = RPCSelectCCPolicies()
	}
	for _, cc_policy := range cc_policies_list {
		cc_policies.Store(cc_policy.AppID, cc_policy)
		//fmt.Println("InitCCPolicy:", cc_policy.AppID, cc_policy)
	}
}

func UpdateCCPolicy(param map[string]interface{}) error {
	cc_policy_map := param["object"].(map[string]interface{})
	app_id := int64(param["id"].(float64))
	interval_seconds := time.Duration(cc_policy_map["interval_seconds"].(float64))
	max_count := int64(cc_policy_map["max_count"].(float64))
	block_seconds := time.Duration(cc_policy_map["block_seconds"].(float64))
	action := models.PolicyAction(cc_policy_map["action"].(float64))
	stat_by_url := cc_policy_map["stat_by_url"].(bool)
	stat_by_ua := cc_policy_map["stat_by_ua"].(bool)
	stat_by_cookie := cc_policy_map["stat_by_cookie"].(bool)
	is_enabled := cc_policy_map["is_enabled"].(bool)
	exist_app_id := data.DAL.ExistsCCPolicyByAppID(app_id)
	if exist_app_id == false {
		// new policy
		err := data.DAL.InsertCCPolicy(app_id, interval_seconds, max_count, block_seconds, action, stat_by_url, stat_by_ua, stat_by_cookie, is_enabled)
		if err != nil {
			return err
		}
		cc_policy := &models.CCPolicy{
			AppID:           app_id,
			IntervalSeconds: interval_seconds, MaxCount: max_count, BlockSeconds: block_seconds,
			Action: action, StatByURL: stat_by_url, StatByUserAgent: stat_by_ua, StatByCookie: stat_by_cookie,
			IsEnabled: is_enabled}
		//cc_policies[app_id] = cc_policy
		cc_policies.Store(app_id, cc_policy)
		if cc_policy.IsEnabled == true {
			go CCAttackTick(app_id)
		}
	} else {
		// update policy
		err := data.DAL.UpdateCCPolicy(interval_seconds, max_count, block_seconds, action, stat_by_url, stat_by_ua, stat_by_cookie, is_enabled, app_id)
		if err != nil {
			return err
		}
		cc_policy := GetCCPolicyByAppID(app_id)
		if cc_policy.IntervalSeconds != interval_seconds {
			cc_policy.IntervalSeconds = interval_seconds
			app_cc_ticker, _ := cc_tickers.Load(app_id)
			cc_ticker := app_cc_ticker.(*time.Ticker)
			cc_ticker.Stop()
		}
		cc_policy.MaxCount = max_count
		cc_policy.BlockSeconds = block_seconds
		cc_policy.StatByURL = stat_by_url
		cc_policy.StatByUserAgent = stat_by_ua
		cc_policy.StatByCookie = stat_by_cookie
		cc_policy.Action = action
		cc_policy.IsEnabled = is_enabled
		//cc_policy.Description=description
		if cc_policy.IsEnabled == true {
			go CCAttackTick(app_id)
		}
	}
	data.UpdateFirewallLastModified()
	return nil
}

func DeleteCCPolicyByAppID(app_id int64) error {
	if app_id == 0 {
		return errors.New("Global CC Policy cannot be deleted.")
	}
	data.DAL.DeleteCCPolicy(app_id)
	cc_policies.Delete(app_id)
	if app_cc_ticker, ok := cc_tickers.Load(app_id); ok {
		cc_ticker := app_cc_ticker.(*time.Ticker)
		if cc_ticker != nil {
			cc_ticker.Stop()
		}
	}
	data.UpdateFirewallLastModified()
	return nil
}
