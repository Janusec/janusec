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
	ccPoliciesList []*models.CCPolicy
	ccPolicies     sync.Map //map[int64]*models.CCPolicy // key: appID==0  Global Policy
	ccCounts       sync.Map //map[int64]*(map[string]*models.ClientStat) // appID, clientID, ClientStat
	ccTickers      sync.Map //map[int64]*time.Ticker
)

func ClearCCStatByClientID(policyAppID int64, clientID string) {
	if ccCount, ok := ccCounts.Load(policyAppID); ok {
		appCCCount := ccCount.(*sync.Map)
		appCCCount.Delete(clientID)
	}
}

func CCAttackTick(appID int64) {
	if appCCTicker, ok := ccTickers.Load(appID); ok {
		ccTicker := appCCTicker.(*time.Ticker)
		ccTicker.Stop()
	}
	ccPolicyMap, _ := ccPolicies.Load(appID)
	ccPolicy := ccPolicyMap.(*models.CCPolicy)
	ccTicker := time.NewTicker(ccPolicy.IntervalSeconds * time.Second)

	ccTickers.Store(appID, ccTicker)
	for range ccTicker.C {
		ccCount, _ := ccCounts.LoadOrStore(appID, &sync.Map{})
		//fmt.Println("CCAttackTick AppID=", appID, time.Now())
		appCCCount := ccCount.(*sync.Map)
		appCCCount.Range(func(key, value interface{}) bool {
			clientID := key.(string)
			stat := value.(*models.ClientStat)
			//fmt.Println("CCAttackTick:", appID, clientID, stat)
			if stat.IsBlackIP == true {
				stat.RemainSeconds -= ccPolicy.IntervalSeconds
				if stat.RemainSeconds <= 0 {
					appCCCount.Delete(clientID)
				}
			} else if stat.Count >= ccPolicy.MaxCount {
				stat.Count = 0
				stat.IsBlackIP = true
				stat.RemainSeconds = ccPolicy.BlockSeconds
			} else {
				appCCCount.Delete(clientID)
			}
			return true
		})
	}
}

func GetCCPolicyByAppID(appID int64) *models.CCPolicy {
	if ccPolicy, ok := ccPolicies.Load(appID); ok {
		return ccPolicy.(*models.CCPolicy)
	}
	ccPolicy, _ := ccPolicies.Load(int64(0))
	return ccPolicy.(*models.CCPolicy)
}

func GetCCPolicies() ([]*models.CCPolicy, error) {
	return ccPoliciesList, nil
}

func GetCCPolicyRespByAppID(appID int64) (*models.CCPolicy, error) {
	ccPolicy := GetCCPolicyByAppID(appID)
	return ccPolicy, nil
}

func IsCCAttack(r *http.Request, appID int64, src_ip string) (bool, *models.CCPolicy, string, bool) {
	ccPolicy := GetCCPolicyByAppID(appID)
	if ccPolicy.IsEnabled == false {
		return false, nil, "", false
	}
	if ccPolicy.AppID == 0 {
		appID = 0 // Important: stat within general policy
	}
	ccCount, _ := ccCounts.LoadOrStore(appID, &sync.Map{})
	appCCCount := ccCount.(*sync.Map)
	preHashContent := src_ip
	if ccPolicy.StatByURL == true {
		preHashContent += r.URL.Path
	}
	if ccPolicy.StatByUserAgent == true {
		ua := r.Header.Get("User-Agent")
		preHashContent += ua
	}
	if ccPolicy.StatByCookie == true {
		cookie := r.Header.Get("Cookie")
		preHashContent += cookie
	}
	clientID := data.SHA256Hash(preHashContent)
	clientIDStat, _ := appCCCount.LoadOrStore(clientID, &models.ClientStat{Count: 0, IsBlackIP: false, RemainSeconds: 0})
	clientStat := clientIDStat.(*models.ClientStat)
	if clientStat.IsBlackIP == true {
		needLog := false
		if clientStat.Count == 0 {
			clientStat.Count += 1
			needLog = true
		}
		return true, ccPolicy, clientID, needLog
	}
	clientStat.Count += 1
	//fmt.Println("IsCCAttack:", r.URL.Path, clientID, clientStat.Count, clientStat.IsBlackIP, clientStat.RemainSeconds)
	return false, nil, "", false
}

func InitCCPolicy() {
	//var cc_policies_list []*models.CCPolicy
	if data.IsMaster {
		data.DAL.CreateTableIfNotExistsCCPolicy()
		existCCPolicy := data.DAL.ExistsCCPolicy()
		if existCCPolicy == false {
			data.DAL.InsertCCPolicy(0, 10, 60, 300, models.Action_Block_100, true, true, false, true)
		}
		ccPoliciesList = data.DAL.SelectCCPolicies()
	} else {
		ccPoliciesList = RPCSelectCCPolicies()
	}
	for _, ccPolicy := range ccPoliciesList {
		ccPolicies.Store(ccPolicy.AppID, ccPolicy)
		//fmt.Println("InitCCPolicy:", ccPolicy.AppID, ccPolicy)
	}
}

func UpdateCCPolicy(param map[string]interface{}) error {
	ccPolicyMap := param["object"].(map[string]interface{})
	appID := int64(param["id"].(float64))
	intervalSeconds := time.Duration(ccPolicyMap["interval_seconds"].(float64))
	maxCount := int64(ccPolicyMap["max_count"].(float64))
	blockSeconds := time.Duration(ccPolicyMap["block_seconds"].(float64))
	action := models.PolicyAction(ccPolicyMap["action"].(float64))
	statByUrl := ccPolicyMap["stat_by_url"].(bool)
	statByUA := ccPolicyMap["stat_by_ua"].(bool)
	statByCookie := ccPolicyMap["stat_by_cookie"].(bool)
	isEnabled := ccPolicyMap["is_enabled"].(bool)
	existAppID := data.DAL.ExistsCCPolicyByAppID(appID)
	if existAppID == false {
		// new policy
		err := data.DAL.InsertCCPolicy(appID, intervalSeconds, maxCount, blockSeconds, action, statByUrl, statByUA, statByCookie, isEnabled)
		if err != nil {
			return err
		}
		ccPolicy := &models.CCPolicy{
			AppID:           appID,
			IntervalSeconds: intervalSeconds, MaxCount: maxCount, BlockSeconds: blockSeconds,
			Action: action, StatByURL: statByUrl, StatByUserAgent: statByUA, StatByCookie: statByCookie,
			IsEnabled: isEnabled}
		ccPolicies.Store(appID, ccPolicy)
		if ccPolicy.IsEnabled == true {
			go CCAttackTick(appID)
		}
	} else {
		// update policy
		err := data.DAL.UpdateCCPolicy(intervalSeconds, maxCount, blockSeconds, action, statByUrl, statByUA, statByCookie, isEnabled, appID)
		if err != nil {
			return err
		}
		ccPolicy := GetCCPolicyByAppID(appID)
		if ccPolicy.IntervalSeconds != intervalSeconds {
			ccPolicy.IntervalSeconds = intervalSeconds
			appCCTicker, _ := ccTickers.Load(appID)
			ccTicker := appCCTicker.(*time.Ticker)
			ccTicker.Stop()
		}
		ccPolicy.MaxCount = maxCount
		ccPolicy.BlockSeconds = blockSeconds
		ccPolicy.StatByURL = statByUrl
		ccPolicy.StatByUserAgent = statByUA
		ccPolicy.StatByCookie = statByCookie
		ccPolicy.Action = action
		ccPolicy.IsEnabled = isEnabled
		if ccPolicy.IsEnabled == true {
			go CCAttackTick(appID)
		}
	}
	data.UpdateFirewallLastModified()
	return nil
}

func DeleteCCPolicyByAppID(appID int64) error {
	if appID == 0 {
		return errors.New("Global CC Policy cannot be deleted.")
	}
	data.DAL.DeleteCCPolicy(appID)
	ccPolicies.Delete(appID)
	if appCCTicker, ok := ccTickers.Load(appID); ok {
		ccTicker := appCCTicker.(*time.Ticker)
		if ccTicker != nil {
			ccTicker.Stop()
		}
	}
	data.UpdateFirewallLastModified()
	return nil
}
