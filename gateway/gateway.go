/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:37:57
 * @Last Modified: U2, 2018-07-14 16:37:57
 */

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"../backend"
	"../data"
	"../firewall"
	"../models"
	"../utils"
)

func ReverseHandlerFunc(w http.ResponseWriter, r *http.Request) {
	app := backend.GetApplicationByDomain(r.Host)
	if app == nil {
		block_into := &models.HitInfo{PolicyID: 0, VulnName: "Unknown Host"}
		GenerateBlockPage(w, block_into)
		return
	}
	if (r.TLS == nil) && (app.RedirectHttps == true) {
		RedirectHttpsFunc(w, r)
		return
	}
	r.URL.Scheme = app.InternalScheme
	r.URL.Host = r.Host
	//app_id_str := strconv.Itoa(app.AppID)
	//fmt.Println("ReverseHandlerFunc, r.URL.Path:", r.URL.Path)
	/*
	   is_static := backend.IsStaticDir(domain, r.URL.Path)
	   fmt.Println("is_static:", is_static)
	   if r.Method=="GET" && is_static {
	       static_root := "./cdn_static_files/" + app_id_str + "/"
	       fmt.Println(static_root)
	       staticHandler := http.FileServer(http.Dir(static_root))
	       if strings.HasSuffix(r.URL.Path, "/") {
	           http.ServeFile(w, r, "./static_files/warning.html")
	           return
	       }
	       staticHandler.ServeHTTP(w, r)
	       return
	   }
	*/
	// dynamic
	if app.WAFEnabled {
		src_ip := GetClientIP(r, app)
		if is_cc, cc_policy, client_id := firewall.IsCCAttack(r, app.ID, src_ip); is_cc == true {
			target_url := r.URL.Path
			if len(r.URL.RawQuery) > 0 {
				target_url += "?" + r.URL.RawQuery
			}
			hit_info := &models.HitInfo{TypeID: 1,
				PolicyID: cc_policy.AppID, VulnName: "CC",
				Action: cc_policy.Action, ClientID: client_id,
				TargetURL: target_url, BlockTime: time.Now().Unix()}
			if hit_info.Action == models.Action_Block_100 {
				GenerateBlockPage(w, hit_info)
				return
			}
			if hit_info.Action == models.Action_CAPTCHA_300 {
				captcha_hit_info.Store(hit_info.ClientID, hit_info)
				captcha_url := CaptchaEntrance + "?id=" + hit_info.ClientID
				http.Redirect(w, r, captcha_url, http.StatusTemporaryRedirect)
				return
			}
		}

		if is_hit, policy := firewall.IsRequestHitPolicy(r, app.ID, src_ip); is_hit == true {
			switch policy.Action {
			case models.Action_Block_100:
				vuln_name, _ := firewall.VulnMap.Load(policy.VulnID)
				hit_info := &models.HitInfo{TypeID: 2, PolicyID: policy.ID, VulnName: vuln_name.(string)}
				go firewall.LogGroupHitRequest(r, app.ID, src_ip, policy)
				GenerateBlockPage(w, hit_info)
				return
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
				http.Redirect(w, r, captcha_url, http.StatusTemporaryRedirect)
				return
			default:
				// models.Action_Pass_400 do nothing
			}
		}
	}

	dest := backend.SelectDestination(app)

	// var transport http.RoundTripper
	transport := &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("tcp", dest)
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := net.Dial("tcp", dest)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{ServerName: r.Host}
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil //net.Dial("tcp", dest)
		},
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			//req.URL.Scheme = app.InternalScheme
			//req.URL.Host = r.Host
		},
		Transport:      transport,
		ModifyResponse: rewriteResponse}
	if utils.Debug {
		dump, err := httputil.DumpRequest(r, true)
		utils.CheckError("ReverseHandlerFunc DumpRequest", err)
		fmt.Println(string(dump))
	}
	proxy.ServeHTTP(w, r)
}

// redirect 80 to 443
func RedirectHttpsFunc(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func GenClientID(r *http.Request, app_id int64, src_ip string) string {
	pre_hash_content := src_ip
	url := r.URL.Path
	pre_hash_content += url
	ua := r.Header.Get("User-Agent")
	pre_hash_content += ua
	cookie := r.Header.Get("Cookie")
	pre_hash_content += cookie
	client_id := data.SHA256Hash(pre_hash_content)
	return client_id
}

func GetClientIP(r *http.Request, app *models.Application) (client_ip string) {
	switch app.ClientIPMethod {
	case models.IPMethod_REMOTE_ADDR:
		client_ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		return client_ip
	case models.IPMethod_X_FORWARDED_FOR:
		x_forwarded_for := r.Header.Get("X-Forwarded-For")
		ips := strings.Split(x_forwarded_for, ", ")
		client_ip = ips[len(ips)-1]
	case models.IPMethod_X_REAL_IP:
		client_ip = r.Header.Get("X-Real-IP")
	case models.IPMethod_REAL_IP:
		client_ip = r.Header.Get("Real-IP")
	}
	if len(client_ip) == 0 {
		client_ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return client_ip
}
