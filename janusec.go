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
	"github.com/Janusec/janusec/backend"
	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/firewall"
	"github.com/Janusec/janusec/frontend"
	"github.com/Janusec/janusec/gateway"
	"github.com/Janusec/janusec/settings"
	"github.com/Janusec/janusec/utils"
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
	os.Chdir(exePath)
	runtime.GOMAXPROCS(runtime.NumCPU())
	utils.InitLogger()
	SetOSEnv()
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
	utils.DebugPrintln("Janusec Application Gateway", data.Version, "Starting ...")
	if utils.Debug {
		utils.DebugPrintln("Warning: Janusec is running in Debug mode.")
	}
	data.InitDAL()
	if data.IsMaster {
		backend.InitDatabase()
		settings.InitDefaultSettings() // instanceKey & nodesKey
	}
	backend.LoadAppConfiguration()
	firewall.InitFirewall()
	settings.LoadSettings()

	tlsconfig := &tls.Config{
		GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := backend.GetCertificateByDomain(helloInfo.ServerName)
			return cert, err
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
	}

	if data.IsMaster {
		/*
			adminMux := http.NewServeMux()
			adminMux.HandleFunc("/janusec-api/", frontend.ApiHandlerFunc)
			adminMux.HandleFunc("/", frontend.AdminHandlerFunc)
			adminMux.HandleFunc("/webssh", frontend.WebSSHHandlerFunc)
			adminMux.HandleFunc("/debug/pprof/", pprof.Index)
			adminMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			adminMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			adminMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			adminMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

			go func() {
				listen, _ := net.Listen("tcp", data.CFG.MasterNode.AdminHTTPListen)
				err := http.Serve(listen, adminMux)
				utils.CheckError("Main Admin Listen", err)
			}()
			go func() {
				listen, _ := tls.Listen("tcp", data.CFG.MasterNode.AdminHTTPSListen, tlsconfig)
				utils.CheckError("Main Admin tls.Listen", http.Serve(listen, adminMux))
			}()
		*/
	}
	gateMux := http.NewServeMux()
	// Add API and admin
	gateMux.HandleFunc("/janusec-admin/api", frontend.ApiHandlerFunc)
	gateMux.HandleFunc("/janusec-admin/", frontend.AdminHandlerFunc)
	gateMux.HandleFunc("/janusec-admin/webssh", frontend.WebSSHHandlerFunc)
	// Add CAPTCHA
	gateMux.HandleFunc("/captcha/confirm", gateway.ShowCaptchaHandlerFunc)
	gateMux.HandleFunc("/captcha/validate", gateway.ValidateCaptchaHandlerFunc)
	gateMux.Handle("/captcha/png/", gateway.ShowCaptchaImage())
	// Reverse Proxy
	gateMux.HandleFunc("/", gateway.ReverseHandlerFunc)
	ctxGateMux := AddContextHandler(gateMux)
	go func() {
		listen, _ := net.Listen("tcp", ":80")
		utils.CheckError("Listen 80 Failed", http.Serve(listen, ctxGateMux))
	}()
	//go func() {
	listen, _ := tls.Listen("tcp", ":443", tlsconfig)
	utils.CheckError("Listen 443 Failed", http.Serve(listen, ctxGateMux))
	//}()
}

// AddContextHandler to add context handler
func AddContextHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// map[GroupPolicyID int64](Value int64)
		ctx := context.WithValue(r.Context(), "groupPolicyHitValue", &sync.Map{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SetOSEnv() {
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
	cmd := exec.Command("sysctl", "-w", "net.core.somaxconn=65535")
	err = cmd.Run()
	if err != nil {
		utils.DebugPrintln("sysctl set net.core.somaxconn error:", err)
	}
	cmd = exec.Command("sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=1024000")
	err = cmd.Run()
	if err != nil {
		utils.DebugPrintln("sysctl set net.ipv4.tcp_max_syn_backlog error:", err)
	}
}
