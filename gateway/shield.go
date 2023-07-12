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
		tmplShieldReq, _ = template.New("shieldReq").Parse(data.NodeSetting.ShieldHTML)
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
