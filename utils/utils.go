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
	logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0766)
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

func DebugPrintln(a ...interface{}) {
	if Debug {
		log.Println(a)
	} else {
		logger.Println(a)
	}
}
