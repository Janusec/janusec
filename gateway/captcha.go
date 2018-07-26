/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:54
 * @Last Modified: U2, 2018-07-14 16:36:54
 */

package gateway

import (
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/Janusec/janusec/firewall"
	"github.com/Janusec/janusec/models"
	"github.com/dchest/captcha"
)

var (
	captcha_hit_info sync.Map // (client_id string, *HitInfo)
	formTemplate     = template.Must(template.New("captcha").Parse(formTemplateSrc))
)

const (
	CaptchaEntrance = "/captcha/confirm"
)

func ShowCaptchaHandlerFunc(w http.ResponseWriter, r *http.Request) {
	go ClearExpiredCapthchaHitInfo()
	id := r.FormValue("id")
	captcha_context := models.CaptchaContext{CaptchaId: captcha.New(), ClientID: id}
	if err := formTemplate.Execute(w, &captcha_context); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func ValidateCaptchaHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	client_id := r.FormValue("client_id")
	if !captcha.VerifyString(r.FormValue("captcha_id"), r.FormValue("captcha_solution")) {
		captcha_url := CaptchaEntrance + "?id=" + client_id
		http.Redirect(w, r, captcha_url, http.StatusTemporaryRedirect)
	} else {
		if map_hit_info, ok := captcha_hit_info.Load(client_id); ok {
			hit_info := map_hit_info.(*models.HitInfo)
			captcha_hit_info.Delete(client_id)
			if hit_info.TypeID == 1 {
				firewall.ClearCCStatByClientID(hit_info.PolicyID, client_id)
				http.Redirect(w, r, hit_info.TargetURL, http.StatusMovedPermanently)
			} else {
				http.Redirect(w, r, "/", http.StatusMovedPermanently)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}
}

func ShowCaptchaImage() http.Handler {
	return captcha.Server(captcha.StdWidth, captcha.StdHeight)
}

func ClearExpiredCapthchaHitInfo() {
	captcha_hit_info.Range(func(key, value interface{}) bool {
		client_id := key.(string)
		hit_info := value.(*models.HitInfo)
		cur_time := time.Now().Unix()
		if cur_time-hit_info.BlockTime > 600 {
			captcha_hit_info.Delete(client_id)
		}
		return true
	})
}

const formTemplateSrc = `<!doctype html>
<head><title>Captcha Example</title></head>
<body>
<script>
function setSrcQuery(e, q) {
	var src  = e.src;
	var p = src.indexOf('?');
	if (p >= 0) {
		src = src.substr(0, p);
	}
	e.src = src + "?" + q
}

function reload() {
	setSrcQuery(document.getElementById('image'), "reload=" + (new Date()).getTime());
	return false;
}
</script>
<form action="/captcha/validate" method="POST">
<p>Please type the following numbers:</p>
<p><img id=image src="/captcha/png/{{.CaptchaId}}.png" alt="Captcha image"></p>
<a href="#" onclick="reload()">Reload</a>
<input type="hidden" name="captcha_id" value="{{.CaptchaId}}"><br>
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input name="captcha_solution">
<input type="submit" value="Submit">
</form>
`
