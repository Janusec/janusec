/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:17:25
 * @Last Modified: U2, 2018-07-14 16:17:25
 */

package main

import (
	"context"
	"crypto/tls"
	"encoding/gob"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	// _ "net/http/pprof"
	"janusec/backend"
	"janusec/data"
	"janusec/firewall"
	"janusec/gateway"
	"janusec/models"
	"janusec/utils"
)

func main() {
	ver := flag.Bool("version", false, "Display Version Information")
	flag.Parse()
	if *ver {
		fmt.Println(data.Version)
		os.Exit(0)
	}
	dir, _ := os.Executable()
	exePath := filepath.Dir(dir)
	err := os.Chdir(exePath)
	if err != nil {
		utils.CheckError("os.Chdir error", err)
		os.Exit(1)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	utils.InitLogger()
	SetOSEnv()

	utils.DebugPrintln("Janusec Application Gateway", data.Version, "Starting ...")
	if utils.Debug {
		utils.DebugPrintln("Warning: Janusec is running in Debug mode.")
	}
	data.InitConfig()
	if data.IsPrimary {
		backend.InitDatabase()
		data.InitDefaultSettings() // instanceKey & nodesKey
	}
	backend.LoadAppConfiguration()
	firewall.InitFirewall()
	data.LoadSettings()
	if !data.IsPrimary {
		go gateway.SyncTimeTick()
	}
	go gateway.InitAccessStat()
	go gateway.Counter()
	go gateway.DailyRoutineTasks()

	tlsconfig := &tls.Config{
		GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := backend.GetCertificateByDomain(helloInfo)
			return cert, err
		},
		NextProtos: []string{"h2", "http/1.1"},
		MaxVersion: tls.VersionTLS13,
		MinVersion: tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	}
	gateMux := http.NewServeMux()
	if data.IsPrimary {
		admin := data.CFG.PrimaryNode.Admin
		if admin.Listen {
			adminMux := http.NewServeMux()
			LoadAPIRoute(adminMux)
			if len(admin.ListenHTTP) > 0 {
				go func() {
					listen, err := net.Listen("tcp", admin.ListenHTTP)
					if err != nil {
						utils.CheckError("Admin Port occupied.", err)
						utils.DebugPrintln("Admin Port occupied.", err)
						os.Exit(1)
					}
					utils.DebugPrintln("Admin Listen HTTP ", admin.ListenHTTP)
					err = http.Serve(listen, adminMux)
					if err != nil {
						utils.CheckError("http.Serve adminMux error", err)
						utils.DebugPrintln("http.Serve adminMux error", err)
						os.Exit(1)
					}
					defer listen.Close()
				}()
			}
			if len(admin.ListenHTTPS) > 0 {
				go func() {
					listen, err := tls.Listen("tcp", admin.ListenHTTPS, tlsconfig)
					if err != nil {
						utils.CheckError("Admin Port occupied.", err)
						utils.DebugPrintln("Admin Port occupied.", err)
						os.Exit(1)
					}
					utils.DebugPrintln("Admin Listen HTTPS", admin.ListenHTTPS)
					err = http.Serve(listen, adminMux)
					if err != nil {
						utils.CheckError("http.Serve adminMux error", err)
						utils.DebugPrintln("http.Serve adminMux error", err)
						os.Exit(1)
					}
					defer listen.Close()
				}()
			}
		} else {
			// Add API and admin
			LoadAPIRoute(gateMux)
		}
	}
	// Add OAuth2
	gateMux.HandleFunc("/oauth/logout", gateway.OAuthLogout)
	gateMux.HandleFunc("/oauth/wxwork", gateway.WxworkCallBackHandleFunc)
	gateMux.HandleFunc("/oauth/dingtalk", gateway.DingtalkCallBackHandleFunc)
	gateMux.HandleFunc("/oauth/feishu", gateway.FeishuCallBackHandleFunc)
	gateMux.HandleFunc("/oauth/lark", gateway.LarkCallBackHandleFunc)
	gateMux.HandleFunc("/oauth/code/register", gateway.ShowAuthCodeRegisterUI)
	gateMux.HandleFunc("/oauth/code/verify", gateway.AuthCodeVerifyFunc)
	// Add CAS2.0
	gateMux.HandleFunc("/oauth/cas2", gateway.CAS2CallBackHandleFunc)
	// LDAP Auth UI
	gateMux.HandleFunc("/ldap/login", gateway.ShowLDAPLoginUI)
	gateMux.HandleFunc("/ldap/auth", gateway.LDAPCallBackHandleFunc)
	// SAML Auth
	gateMux.HandleFunc("/saml/login", gateway.SAMLLogin)
	// Add CAPTCHA
	gateMux.HandleFunc("/captcha/confirm", gateway.ShowCaptchaHandlerFunc)
	gateMux.HandleFunc("/captcha/validate", gateway.ValidateCaptchaHandlerFunc)
	gateMux.Handle("/captcha/png/", gateway.ShowCaptchaImage())
	// Add 5-second shield Authorization
	gateMux.HandleFunc("/.auth/shield", gateway.SecondShieldAuthorization)
	// Test only
	// gateMux.HandleFunc("/.auth/test", gateway.Test)

	// Reverse Proxy
	gateMux.HandleFunc("/", gateway.ReverseHandlerFunc)
	ctxGateMux := AddContextHandler(gateMux)
	go func(listenPort string) {
		listen, err := net.Listen("tcp", listenPort)
		if err != nil {
			msg := "Port " + listenPort + " is occupied."
			utils.CheckError(msg, err)
			utils.DebugPrintln(msg, err)
			os.Exit(1)
		}
		utils.DebugPrintln("Listen HTTP ", listenPort)
		// err = http.Serve(listen, ctxGateMux)
		err = http.Serve(listen, backend.AcmeCertManager.HTTPHandler(ctxGateMux))
		if err != nil {
			utils.CheckError("http.Serve error", err)
			utils.DebugPrintln("http.Serve error", err)
			os.Exit(1)
		}
		defer listen.Close()
	}(data.CFG.ListenHTTP)
	listen, err := tls.Listen("tcp", data.CFG.ListenHTTPS, tlsconfig)
	if err != nil {
		msg := "Port " + data.CFG.ListenHTTPS + " is occupied."
		utils.CheckError(msg, err)
		utils.DebugPrintln(msg, err)
		os.Exit(1)
	}
	utils.DebugPrintln("Listen HTTPS", data.CFG.ListenHTTPS)
	//err = http.Serve(listen, ctxGateMux)
	err = http.Serve(listen, backend.AcmeCertManager.HTTPHandler(ctxGateMux))
	if err != nil {
		utils.CheckError("http.Serve error", err)
		utils.DebugPrintln("http.Serve error", err)
		os.Exit(1)
	}
	defer listen.Close()
}

// AddContextHandler to add context handler
func AddContextHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// map[GroupPolicyID int64](Value int64)
		ctx := context.WithValue(r.Context(), models.PolicyKey("groupPolicyHitValue"), &sync.Map{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoadAPIRoute set HandleFunc
func LoadAPIRoute(mux *http.ServeMux) {
	mux.HandleFunc("/janusec-admin/api", gateway.ReplicaAPIHandlerFunc)
	mux.HandleFunc("/janusec-admin/ui-api", gateway.AdminAPIHandlerFunc)
	mux.HandleFunc("/janusec-admin/webssh", gateway.WebSSHHandlerFunc)
	mux.HandleFunc("/janusec-admin/oauth/get", gateway.OAuthGetHandleFunc)
	mux.HandleFunc("/janusec-admin/", gateway.AdminHandlerFunc)
}

// SetOSEnv set environment
func SetOSEnv() {
	// Enable TLS 1.3 for golang 1.12, not required in golang 1.14
	// os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
	// Enable gorilla/sessions support struct
	gob.Register(models.AuthUser{})
	/*
		#!/bin/bash
		ulimit -n 1024000
		sysctl -w net.core.somaxconn=65535
		sysctl -w net.ipv4.tcp_max_syn_backlog=1024000
	*/
	rLimit := syscall.Rlimit{Cur: 1024000, Max: 1024000}
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		utils.DebugPrintln("Setrlimit", err)
	}
	cmd := exec.Command("/usr/sbin/sysctl", "-w", "net.core.somaxconn=65535")
	err = cmd.Run()
	if err != nil {
		cmd = exec.Command("/sbin/sysctl", "-w", "net.core.somaxconn=65535")
		err = cmd.Run()
		if err != nil {
			utils.DebugPrintln("sysctl set net.core.somaxconn error:", err)
		}
	}
	cmd = exec.Command("/usr/sbin/sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=1024000")
	err = cmd.Run()
	if err != nil {
		cmd = exec.Command("/sbin/sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=1024000")
		err = cmd.Run()
		if err != nil {
			utils.DebugPrintln("sysctl set net.ipv4.tcp_max_syn_backlog error:", err)
		}
	}
}
