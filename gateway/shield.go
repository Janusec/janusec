/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2021-05-02 15:27:30
 * @Last Modified: U2, 2021-05-02 15:27:30
 */

package gateway

import (
	"html/template"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net/http"
	"regexp"
	"time"

	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

var (
	tmplShieldReq *template.Template
	shieldCache   = cache.New(5*time.Second, 5*time.Second)
)

func IsSearchEngine(ua string) bool {
	matched, err := regexp.MatchString(data.NodeSetting.SearchEnginesPattern, ua)
	if err != nil {
		utils.DebugPrintln("ReverseHandlerFunc Search Engines MatchString", err)
	}
	return matched
}

func IsCrawler(r *http.Request, srcIP string) bool {
	count, found := shieldCache.Get(srcIP)
	if found {
		nowCount := count.(int64) + int64(1)
		if nowCount > 3 {
			// Found crawler
			return true
		}
		shieldCache.Set(srcIP, nowCount, cache.DefaultExpiration)
	} else {
		shieldCache.Set(srcIP, int64(1), cache.DefaultExpiration)
	}
	return false
}

// SecondShieldAuthorization give authorization
func SecondShieldAuthorization(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "janusec-token")
	// First, check time interval
	timestampI := session.Values["timestamp"]
	if timestampI == nil {
		// show 5-second shield
		GenerateShieldPage(w, r, r.URL.Path)
		return
	}
	timestamp := timestampI.(int64)
	now := time.Now().Unix()
	if now-timestamp < 5 {
		GenerateShieldPage(w, r, r.URL.Path)
		return
	}
	session.Values["shldtoken"] = now
	// 5-second shield session will be invalid when user close the browser.
	session.Options = &sessions.Options{Path: "/", HttpOnly: true}
	err := session.Save(r, w)
	if err != nil {
		utils.DebugPrintln("session save error", err)
	}
	callback := r.FormValue("callback")
	http.Redirect(w, r, callback, http.StatusTemporaryRedirect)
}

// GenerateShieldPage for first access if 5-second shield enabled
func GenerateShieldPage(w http.ResponseWriter, r *http.Request, urlPath string) {
	if tmplShieldReq == nil {
		tmplShieldReq, _ = template.New("shieldReq").Parse(shieldHTML)
	}
	session, _ := store.Get(r, "janusec-token")
	session.Values["timestamp"] = time.Now().Unix()
	// 5-second shield session will be invalid when user close the browser.
	session.Options = &sessions.Options{Path: "/", HttpOnly: true}
	err := session.Save(r, w)
	if err != nil {
		utils.DebugPrintln("session save error", err)
	}
	w.WriteHeader(200)
	err = tmplShieldReq.Execute(w, models.ShieldInfo{Callback: urlPath})
	if err != nil {
		utils.DebugPrintln("GenerateShieldPage tmpl.Execute error", err)
	}
}

const shieldHTML = `<!DOCTYPE html>
<html>
<head>
<title>Checking</title>
</head>
<style>
body {
    font-family: Arial, Helvetica, sans-serif;
    text-align: center;
}

.text-logo {
    display: block;
	width: 260px;
    font-size: 48px;  
    background-color: #F9F9F9;    
    color: #f5f5f5;    
    text-decoration: none;
    text-shadow: 2px 2px 4px #000000;
    box-shadow: 2px 2px 3px #D5D5D5;
    padding: 15px; 
    margin: auto;    
}

.block_div {
    padding: 10px;
    width: 70%;    
    margin: auto;
}

</style>
<body>
<div class="block_div">
<h1 class="text-logo">JANUSEC</h1>
<hr>
<p>
Checking your browser, please wait <span id="countdown">5</span> seconds ...
</p>
</div>
<script>
var t=5;
var countdown=setInterval(function(){	
	t--;
	document.getElementById("countdown").innerHTML=t;
	if(t<=0) {
		clearInterval(countdown);
		window.location.href = "/.auth/shield?callback={{ .Callback }}";
	}
}, 1000);
</script>
</body>
</html>
`
