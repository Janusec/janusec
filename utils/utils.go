/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:20:49
 * @Last Modified: U2, 2018-07-14 16:20:49
 */

package utils

import (
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	logger *log.Logger
	Debug  = false
)

func CheckError(msg string, err error) {
	if err != nil {
		log.Println(msg, err)
	}
}

func InitLogger() {
	logFilename := "./log/janusec" + time.Now().Format("20060102") + ".log"
	logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		CheckError("InitLogger", err)
		os.Exit(1)
	}
	logger = log.New(logFile, "[Janusec] ", log.LstdFlags)
}

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
		log.Println(a)
	} else {
		logger.Println(a)
	}
}

// AccessLog record log for each application
func AccessLog(domain string, method string, ip string, url string, ua string) {
	now := time.Now()
	f, err := os.OpenFile("./log/"+domain+now.Format("20060102")+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Println("error opening file: %v", err)
	}
	log.SetOutput(f)
	log.Printf("[%s] %s [%s] UA:[%s]\n", ip, method, url, ua)
	if err := f.Close(); err != nil {
		log.Println("error closing file: %v", err)
	}
}
