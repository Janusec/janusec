/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:10
 * @Last Modified: U2, 2018-07-14 16:38:10
 */

package gateway

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"
	//"net/http/httputil"
	"strings"
	//"io/ioutil"
	"../backend"
	"../firewall"
	"../models"
	"../utils"
)

func rewriteResponse(resp *http.Response) (err error) {
	utils.DebugPrintln("rewriteResponse")
	r := resp.Request
	app := backend.GetApplicationByDomain(r.Host)
	location_url, err := resp.Location()
	if location_url != nil {
		port := location_url.Port()
		if (port != "80") && (port != "443") {
			host := location_url.Hostname()
			//app := backend.GetApplicationByDomain(host)
			if app != nil {
				new_location := strings.Replace(location_url.String(), host+":"+port, host, -1)
				user_scheme := "http"
				if resp.Request.TLS != nil {
					user_scheme = "https"
				}
				new_location = strings.Replace(new_location, location_url.Scheme, user_scheme, 1)
				//fmt.Println("new_location", new_location)
				resp.Header.Set("Location", new_location)
			}
		}
	}
	//src_ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if app.WAFEnabled {
		src_ip := GetClientIP(r, app)
		if is_hit, policy := firewall.IsResponseHitPolicy(resp, app.ID); is_hit {
			switch policy.Action {
			case models.Action_Block_100:
				vuln_name, _ := firewall.VulnMap.Load(policy.VulnID)
				hit_info := &models.HitInfo{TypeID: 2, PolicyID: policy.ID, VulnName: vuln_name.(string)}
				go firewall.LogGroupHitRequest(r, app.ID, src_ip, policy)
				block_content := GenerateBlockConcent(hit_info)
				//fmt.Println("rewriteResponse Action_Block_100 block_content", string(block_content))
				body := ioutil.NopCloser(bytes.NewReader(block_content))
				resp.Body = body
				resp.ContentLength = int64(len(block_content))
				resp.StatusCode = 403
				return nil
			case models.Action_BypassAndLog_200:
				go firewall.LogGroupHitRequest(r, app.ID, src_ip, policy)
			case models.Action_CAPTCHA_300:
				client_id := GenClientID(r, app.ID, src_ip)
				target_url := r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target_url += "?" + r.URL.RawQuery
				}
				hit_info := &models.HitInfo{TypeID: 2,
					PolicyID: policy.ID, VulnName: "Group Policy Hit",
					Action: policy.Action, ClientID: client_id,
					TargetURL: target_url, BlockTime: time.Now().Unix()}
				captcha_hit_info.Store(client_id, hit_info)
				captcha_url := CaptchaEntrance + "?id=" + client_id
				resp.Header.Set("Location", captcha_url)
				resp.ContentLength = 0
				//http.Redirect(w, r, captcha_url, http.StatusTemporaryRedirect)
				return
			default:
				// models.Action_Pass_400 do nothing
			}
		}
	}

	// HSTS
	if (app.HSTSEnabled == true) && (resp.Request.TLS != nil) {
		resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	//body, err := httputil.DumpResponse(resp, true)
	//fmt.Println("Dump Response:")
	//fmt.Println(string(body))
	return nil
}
