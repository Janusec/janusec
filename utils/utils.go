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

func DebugPrintln(a ...interface{}) {
	if Debug {
		log.Println(a)
	} else {
		logger.Println(a)
	}
}
