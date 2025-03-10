/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-28 12:45:10
 */

package models

type CookieType int64

const (
	Cookie_Necessary    CookieType = 1
	Cookie_Functional   CookieType = 1 << 1
	Cookie_Analytics    CookieType = 1 << 2
	Cookie_Marketing    CookieType = 1 << 3
	Cookie_Unclassified CookieType = 1 << 9 // 512
)

// Cookie used by applications
type Cookie struct {
	ID          int64      `json:"id,string"`
	AppID       int64      `json:"app_id,string"`
	Name        string     `json:"name"`
	Domain      string     `json:"domain"`
	Path        string     `json:"path"`
	Duration    string     `json:"duration"`
	Vendor      string     `json:"vendor"`
	Type        CookieType `json:"type"`
	Description string     `json:"description"`
	AccessTime  int64      `json:"access_time"`
	Source      string     `json:"source"`
}

// CookieRef used for classification automatically
type CookieRef struct {
	ID          int64           `json:"id,string"`
	Name        string          `json:"name"`
	Vendor      string          `json:"vendor"`
	Type        CookieType      `json:"type"`
	Description string          `json:"description"`
	Operation   CookieOperation `json:"operation"`
}

type CookieOperation int64

const (
	CookieOperation_EqualsString    CookieOperation = 1
	CookieOperation_BeginWithString CookieOperation = 1 << 1
	CookieOperation_RegexMatch      CookieOperation = 1 << 2
)
