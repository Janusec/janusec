/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:20:49
 * @Last Modified: U2, 2018-07-14 16:20:49
 */

package utils

import (
	"log"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	logger *log.Logger

	// Debug , if it is true, more output
	Debug = false
)

// CheckError output to standard console
func CheckError(msg string, err error) {
	if err != nil {
		log.Println(msg, err)
	}
}

// InitLogger for write to log file
func InitLogger() {
	logFilename := "./log/janusec" + time.Now().Format("20060102") + ".log"
	logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		CheckError("InitLogger", err)
		os.Exit(1)
	}
	logger = log.New(logFile, "[Janusec] ", log.LstdFlags)
}

// GetDirAll ...
func GetDirAll(path string) string {
	i := strings.LastIndex(path, "/")
	dirAll := path[:i]
	return dirAll
}

// GetRoutePath return `/abc/` if path = `/abc/xyz/1.php` , return `/` if path = `/abc?id=1`
func GetRoutePath(path string) string {
	regex, _ := regexp.Compile(`^/(\w+/)?`)
	routePath := regex.FindString(path)
	return routePath
}

// DebugPrintln used for log of error
func DebugPrintln(a ...interface{}) {
	if Debug {
		log.Println(a...)
	} else {
		logger.Println(a...)
	}
}

// AccessLog record log for each application
func AccessLog(domain string, method string, ip string, url string, ua string) {
	now := time.Now()
	f, err := os.OpenFile("./log/"+domain+now.Format("20060102")+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file: %s\n", err.Error())
	}
	log.SetOutput(f)
	log.Printf("[%s] %s [%s] UA:[%s]\n", ip, method, url, ua)
	if err := f.Close(); err != nil {
		log.Printf("error closing file: %s\n", err.Error())
	}
}

// VipAccessLog record logs of port forwarding
func VipAccessLog(name string, clientAddr string, gateAddr string, backendAddr string) {
	now := time.Now()
	f, err := os.OpenFile("./log/PortForwarding"+now.Format("20060102")+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file: %s\n", err.Error())
	}
	log.SetOutput(f)
	log.Printf("[%s] [%s] -> [%s] -> [%s]\n", name, clientAddr, gateAddr, backendAddr)
	if err := f.Close(); err != nil {
		log.Printf("error closing file: %s\n", err.Error())
	}
}

// AuthLog record log for each successful authentication
func AuthLog(ip string, username string, provider string, callback string) {
	now := time.Now()
	f, err := os.OpenFile("./log/auth"+now.Format("20060102")+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file: %s\n", err.Error())
	}
	log.SetOutput(f)
	log.Printf("[%s] [%s] [%s] [%s]\n", ip, username, provider, callback)
	if err := f.Close(); err != nil {
		log.Printf("error closing file: %s\n", err.Error())
	}
}

// OperationLog ...
func OperationLog(ip string, username string, operation string, object string) {
	now := time.Now()
	f, err := os.OpenFile("./log/operation"+now.Format("20060102")+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file: %s\n", err.Error())
	}
	log.SetOutput(f)
	log.Printf("[%s] [%s] [%s] [%s]\n", ip, username, operation, object)
	if err := f.Close(); err != nil {
		log.Printf("error closing file: %s\n", err.Error())
	}
}

// SendEmail for notification
func SendEmail(host string, port string, username string, password string, recipients string, subject string, body string) {
	// Set up authentication information.
	auth := smtp.PlainAuth("", username, password, host)

	// recipients example: abc@janusec.com;xyz@janusec.com
	to := strings.Split(recipients, ";")

	msg := []byte("To: " + recipients + "\r\n" +
		"From: " + username + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		"<html><body><p>" +
		body + "\r\n" +
		"</p><hr><p><small>Send by Janusec Application Gateway</small></p>" +
		"</body></html>\r\n")
	err := smtp.SendMail(host+":"+port, auth, username, to, msg)
	if err != nil {
		DebugPrintln("SendEmail error:", err)
	} else {
		DebugPrintln("SendEmail OK to "+recipients, subject)
	}
}
