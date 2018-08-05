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

	"github.com/Janusec/janusec/backend"
	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/firewall"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
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
	//appID_str := strconv.Itoa(app.AppID)
	//fmt.Println("ReverseHandlerFunc, r.URL.Path:", r.URL.Path)
	/*
	   is_static := backend.IsStaticDir(domain, r.URL.Path)
	   fmt.Println("is_static:", is_static)
	   if r.Method=="GET" && is_static {
	       static_root := "./cdn_static_files/" + appID_str + "/"
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
		srcIP := GetClientIP(r, app)
		if isCC, ccPolicy, clientID := firewall.IsCCAttack(r, app.ID, srcIP); isCC == true {
			target_url := r.URL.Path
			if len(r.URL.RawQuery) > 0 {
				target_url += "?" + r.URL.RawQuery
			}
			hit_info := &models.HitInfo{TypeID: 1,
				PolicyID: ccPolicy.AppID, VulnName: "CC",
				Action: ccPolicy.Action, ClientID: clientID,
				TargetURL: target_url, BlockTime: time.Now().Unix()}
			if hit_info.Action == models.Action_Block_100 {
				GenerateBlockPage(w, hit_info)
				return
			}
			if hit_info.Action == models.Action_CAPTCHA_300 {
				captchaHitInfo.Store(hit_info.ClientID, hit_info)
				captcha_url := CaptchaEntrance + "?id=" + hit_info.ClientID
				http.Redirect(w, r, captcha_url, http.StatusTemporaryRedirect)
				return
			}
		}

		if is_hit, policy := firewall.IsRequestHitPolicy(r, app.ID, srcIP); is_hit == true {
			switch policy.Action {
			case models.Action_Block_100:
				vuln_name, _ := firewall.VulnMap.Load(policy.VulnID)
				hit_info := &models.HitInfo{TypeID: 2, PolicyID: policy.ID, VulnName: vuln_name.(string)}
				go firewall.LogGroupHitRequest(r, app.ID, srcIP, policy)
				GenerateBlockPage(w, hit_info)
				return
			case models.Action_BypassAndLog_200:
				go firewall.LogGroupHitRequest(r, app.ID, srcIP, policy)
			case models.Action_CAPTCHA_300:
				clientID := GenClientID(r, app.ID, srcIP)
				target_url := r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target_url += "?" + r.URL.RawQuery
				}
				hit_info := &models.HitInfo{TypeID: 2,
					PolicyID: policy.ID, VulnName: "Group Policy Hit",
					Action: policy.Action, ClientID: clientID,
					TargetURL: target_url, BlockTime: time.Now().Unix()}
				captchaHitInfo.Store(clientID, hit_info)
				captcha_url := CaptchaEntrance + "?id=" + clientID
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

func GenClientID(r *http.Request, appID int64, srcIP string) string {
	preHashContent := srcIP
	url := r.URL.Path
	preHashContent += url
	ua := r.Header.Get("User-Agent")
	preHashContent += ua
	cookie := r.Header.Get("Cookie")
	preHashContent += cookie
	clientID := data.SHA256Hash(preHashContent)
	return clientID
}

func GetClientIP(r *http.Request, app *models.Application) (clientIP string) {
	switch app.ClientIPMethod {
	case models.IPMethod_REMOTE_ADDR:
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		return clientIP
	case models.IPMethod_X_FORWARDED_FOR:
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		ips := strings.Split(xForwardedFor, ", ")
		clientIP = ips[len(ips)-1]
	case models.IPMethod_X_REAL_IP:
		clientIP = r.Header.Get("X-Real-IP")
	case models.IPMethod_REAL_IP:
		clientIP = r.Header.Get("Real-IP")
	}
	if len(clientIP) == 0 {
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return clientIP
}
