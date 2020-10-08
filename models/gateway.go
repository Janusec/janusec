/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:03
 * @Last Modified: U2, 2018-07-14 16:39:03
 */

package models

type HitInfo struct {
	TypeID    int64 // 1: CCPolicy  2:GroupPolicy
	PolicyID  int64
	VulnName  string
	Action    PolicyAction
	ClientID  string // for CC/Attack Client ID
	TargetURL string // for CAPTCHA redirect
	BlockTime int64
}

type CaptchaContext struct {
	CaptchaId string
	ClientID  string
}

type OAuthState struct {
	CallbackURL string
	UserID      string
	AccessToken string
}

// AccessStat record access statistics
type AccessStat struct {
	AppID      int64  `json:"app_id"`
	URLPath    string `json:"url_path"`
	StatDate   string `json:"stat_date"` // Format("20060102")
	Delta      int64  `json:"delta"`
	UpdateTime int64  `json:"update_time"` // Used for expired cleanup
}

// PopularContent i.e. top visited URL Path
type PopularContent struct {
	AppID   int64  `json:"app_id"`
	URLPath string `json:"url_path"`
	Amount  int64  `json:"amount"`
}
