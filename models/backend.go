/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:41
 * @Last Modified: U2, 2018-07-14 16:38:41
 */

package models

import (
	"crypto/tls"
	"database/sql"
	"sync"
)

// Application i.e. Web site
type Application struct {
	ID             int64          `json:"id,string"`
	Name           string         `json:"name"`
	InternalScheme string         `json:"internal_scheme"` // http, https
	Destinations   []*Destination `json:"destinations"`

	// Route: map[string][]*Destination
	// {"/abc/": ["192.168.1.1:8800", "192.168.1.2:8800"], ".php": [...], "/": [...]}
	Route sync.Map `json:"-"`

	Domains       []*Domain `json:"domains"`
	RedirectHTTPS bool      `json:"redirect_https"`
	HSTSEnabled   bool      `json:"hsts_enabled"`
	WAFEnabled    bool      `json:"waf_enabled"`

	// 5-second shield, v1.2.0
	ShieldEnabled bool `json:"shield_enabled"`

	ClientIPMethod IPMethod `json:"ip_method"`
	Description    string   `json:"description"`
	OAuthRequired  bool     `json:"oauth_required"`
	SessionSeconds int64    `json:"session_seconds"`
	Owner          string   `json:"owner"`

	// CSP (Content Security Policy) v0.9.11
	CSPEnabled bool   `json:"csp_enabled"`
	CSP        string `json:"csp"`

	// CacheEnabled cache static files v1.2.5
	CacheEnabled bool `json:"cache_enabled"`

	// Cookie Consent Management v1.4.1
	CookieMgmtEnabled  bool   `json:"cookie_mgmt_enabled"`
	ConciseNotice      string `json:"concise_notice"`
	LongNoticeLink     string `json:"long_notice_link"`
	NecessaryNotice    string `json:"necessary_notice"`
	AnalyticsNotice    string `json:"analytics_notice"`
	EnableAnalytics    bool   `json:"enable_analytics"`
	MarketingNotice    string `json:"marketing_notice"`
	EnableMarketing    bool   `json:"enable_marketing"`
	UnclassifiedNotice string `json:"unclassified_notice"`
	EnableUnclassified bool   `json:"enable_unclassified"`
}

// DBApplication for storage in database
type DBApplication struct {
	ID             int64  `json:"id,string"`
	Name           string `json:"name"`
	InternalScheme string `json:"internal_scheme"` // http, https
	RedirectHTTPS  bool   `json:"redirect_https"`
	HSTSEnabled    bool   `json:"hsts_enabled"`
	WAFEnabled     bool   `json:"waf_enabled"`

	// 5-second shield, v1.2.0
	ShieldEnabled bool `json:"shield_enabled"`

	ClientIPMethod IPMethod `json:"ip_method"`
	Description    string   `json:"description"`
	OAuthRequired  bool     `json:"oauth_required"`
	SessionSeconds int64    `json:"session_seconds"`
	Owner          string   `json:"owner"`
	// CSP (Content Security Policy) v0.9.11
	CSPEnabled bool   `json:"csp_enabled"`
	CSP        string `json:"csp"`
	// CacheEnabled cache static files v1.2.5
	CacheEnabled bool `json:"cache_enabled"`

	// Cookie Consent Management v1.4.1
	CookieMgmtEnabled  bool   `json:"cookie_mgmt_enabled"`
	ConciseNotice      string `json:"concise_notice"`
	LongNoticeLink     string `json:"long_notice_link"`
	NecessaryNotice    string `json:"necessary_notice"`
	AnalyticsNotice    string `json:"analytics_notice"`
	EnableAnalytics    bool   `json:"enable_analytics"`
	MarketingNotice    string `json:"marketing_notice"`
	EnableMarketing    bool   `json:"enable_marketing"`
	UnclassifiedNotice string `json:"unclassified_notice"`
	EnableUnclassified bool   `json:"enable_unclassified"`
}

type DomainRelation struct {
	App      *Application
	Cert     *CertItem
	Redirect bool
	Location string
}

type Domain struct {
	ID       int64        `json:"id,string"`
	Name     string       `json:"name"`
	AppID    int64        `json:"app_id,string"`
	CertID   int64        `json:"cert_id,string"`
	Redirect bool         `json:"redirect"`
	Location string       `json:"location"`
	App      *Application `json:"-"`
	Cert     *CertItem    `json:"-"`
}

type DBDomain struct {
	ID       int64  `json:"id,string"`
	Name     string `json:"name"`
	AppID    int64  `json:"app_id,string"`
	CertID   int64  `json:"cert_id,string"`
	Redirect bool   `json:"redirect"`
	Location string `json:"location"`
}

// RouteType used for backend routing
type RouteType int64

const (
	// ReverseProxyRoute used for secondary application /abc/ /xyz/
	ReverseProxyRoute RouteType = 1

	// FastCGIRoute used for PHP etc.
	FastCGIRoute RouteType = 1 << 1

	// StaticRoute used for static web server
	StaticRoute RouteType = 1 << 2

	// K8S_Ingress used for k8s pods, added on 2023.01.22
	K8S_Ingress RouteType = 1 << 3
)

// Destination is used for backend routing
type Destination struct {
	ID int64 `json:"id,string"`

	// 0.9.8+
	RouteType RouteType `json:"route_type"`

	// 0.9.8+
	RequestRoute string `json:"request_route"`

	// 0.9.8+
	BackendRoute string `json:"backend_route"`

	// Destination is backend IP:Port , or static directory
	Destination string `json:"destination"`

	// PodsAPI example: http://127.0.0.1:8080/api/v1/namespaces/default/pods
	PodsAPI string `json:"pods_api"`
	// PodPort: port of backend pods
	PodPort string `json:"pod_port"`
	// Pods are all destinations
	Pods string `json:"pods"`

	AppID  int64 `json:"app_id,string"`
	NodeID int64 `json:"node_id,string"`

	// Online status of Destination (IP:Port), added in V0.9.11
	Online    bool  `json:"online"`
	CheckTime int64 `json:"check_time"`

	// added in 1.3.1, K8s routine updating and avoid race
	Mutex      sync.RWMutex `json:"-"`
	IsUpdating bool         `json:"-"`
}

// PODS for k8s /api/v1/namespaces/default/pods
type PODS struct {
	Items []Item `json:"items"`
}

type Item struct {
	Status PodStatus `json:"status"`
}

type PodStatus struct {
	Phase string `json:"phase"`
	PodIP string `json:"podIP"`
}

type CertItem struct {
	ID             int64           `json:"id,string"`
	CommonName     string          `json:"common_name"`
	CertContent    string          `json:"cert_content"`
	PrivKeyContent string          `json:"priv_key_content"`
	TlsCert        tls.Certificate `json:"-"`
	ExpireTime     int64           `json:"expire_time"`
	Description    string          `json:"description"`
}

type DBCertItem struct {
	ID               int64
	CommonName       string
	CertContent      string
	EncryptedPrivKey []byte
	ExpireTime       int64
	Description      sql.NullString
}

type IPMethod int64

const (
	IPMethod_REMOTE_ADDR     IPMethod = 1
	IPMethod_X_FORWARDED_FOR IPMethod = 1 << 1
	IPMethod_X_REAL_IP       IPMethod = 1 << 2
	IPMethod_REAL_IP         IPMethod = 1 << 3
)

// VipApp configuration, added from 0.9.12, database table name forwarding_app
type VipApp struct {
	ID int64 `json:"id,string"`

	Name string `json:"name"`

	// Port on Gateway
	ListenPort int64 `json:"listen_port"`

	// IsTCP: true for TCP, false for UDP
	IsTCP bool `json:"is_tcp"`

	// Targets, memory use only, not save to database
	Targets []*VipTarget `json:"targets"`

	// Route: map[port][]*VipTarget
	// {3001: ["192.168.1.1:3306", "192.168.1.2:3306"], 3002: [...]}
	// Route sync.Map `json:"-"`

	Owner string `json:"owner"`

	Description string `json:"description"`

	// ExitChan used for exit, when VipApp deleted or port changed.
	ExitChan chan bool `json:"-"`
}

// VipTarget added from 0.9.12
type VipTarget struct {
	ID       int64 `json:"id,string"`
	VipAppID int64 `json:"vip_app_id,string"`

	// RouteType: Reverse_Proxy, K8S_Ingress
	RouteType RouteType `json:"route_type"`

	// Destination is backend IP:Port
	Destination string `json:"destination"`

	// PodsAPI example: http://127.0.0.1:8080/api/v1/namespaces/default/pods
	PodsAPI string `json:"pods_api"`
	// PodPort: port of backend pods
	PodPort string `json:"pod_port"`
	// Pods are all destinations
	Pods string `json:"pods"`

	// Online status of Destination (IP:Port)
	Online    bool  `json:"online"`
	CheckTime int64 `json:"check_time"`
}
