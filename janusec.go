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
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"

	_ "net/http/pprof"

	"./backend"
	"./data"
	"./firewall"
	"./frontend"
	"./gateway"
	"./settings"
	"./utils"
)

func main() {
	ver := flag.Bool("version", false, "Display Version Information")
	flag.Parse()
	if *ver {
		fmt.Println(data.Version)
		os.Exit(0)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())

	go func() {
		http.ListenAndServe("0.0.0.0:9088", nil)
	}()

	log.Printf("Janusec Application Gateway %s Starting ...\n", data.Version)
	utils.DebugPrintln("Warning: Janusec is running in Debug mode.")
	data.InitDAL()
	if data.IsMaster {
		backend.InitDatabase()
		settings.InitDefaultSettings() // instance_key
	}
	backend.LoadAppConfiguration()
	firewall.InitFirewall()
	settings.LoadSettings()

	tlsconfig := &tls.Config{
		GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := backend.GetCertificateByDomain(helloInfo.ServerName)
			return cert, err
		},
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
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/janusec-api/", frontend.ApiHandlerFunc)
		adminMux.HandleFunc("/", frontend.AdminHandlerFunc)

		go func() {
			listen, _ := net.Listen("tcp", data.CFG.MasterNode.AdminHTTPListen)
			err := http.Serve(listen, adminMux)
			utils.CheckError("Main Admin Listen", err)
		}()
		go func() {
			listen, _ := tls.Listen("tcp", data.CFG.MasterNode.AdminHTTPSListen, tlsconfig)
			utils.CheckError("Main Admin tls.Listen", http.Serve(listen, adminMux))
		}()
	}
	gateMux := http.NewServeMux()
	gateMux.HandleFunc("/", gateway.ReverseHandlerFunc)
	gateMux.HandleFunc("/captcha/confirm", gateway.ShowCaptchaHandlerFunc)
	gateMux.HandleFunc("/captcha/validate", gateway.ValidateCaptchaHandlerFunc)
	gateMux.Handle("/captcha/png/", gateway.ShowCaptchaImage())
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

func AddContextHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// map[GroupPolicyID int64](Value int64)
		ctx := context.WithValue(r.Context(), "group_policy_hit_value", &sync.Map{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
