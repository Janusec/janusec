/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:30
 * @Last Modified: U2, 2018-07-14 16:35:30
 */

package firewall

import (
	"os"
	"syscall"
	"time"

	"janusec/data"
	"janusec/utils"
)

// RoutineCleanLogTick Clear Expired Logs
func RoutineCleanLogTick() {
	if data.IsPrimary {
		routineTicker := time.NewTicker(time.Duration(5*60) * time.Second)
		for range routineTicker.C {
			globalSettings := data.GetGlobalSettings2()
			timeStamp := time.Now().Unix()
			wafLogExpiredTime := timeStamp - (globalSettings.WAFLogDays * 86400)
			err := data.DAL.DeleteHitLogsBeforeTime(wafLogExpiredTime)
			if err != nil {
				utils.DebugPrintln("DeleteHitLogsBeforeTime error", err)
			}
			ccLogExpiredTime := timeStamp - (globalSettings.CCLogDays * 86400)
			err = data.DAL.DeleteCCLogsBeforeTime(ccLogExpiredTime)
			if err != nil {
				utils.DebugPrintln("DeleteCCLogsBeforeTime error", err)
			}
		}
	}
}

// RoutineCleanCacheTick Clean expired cdn files
func RoutineCleanCacheTick() {
	routineTicker := time.NewTicker(time.Duration(7200) * time.Second)
	for range routineTicker.C {
		ClearExpiredFiles("./static/cdncache/", time.Now())
	}
}

// ClearExpiredFiles clear expired static cdn files
func ClearExpiredFiles(path string, now time.Time) {
	fs, err := os.ReadDir(path)
	if err != nil {
		utils.DebugPrintln("ClearExpiredFiles", err)
	}
	for _, file := range fs {
		if file.IsDir() {
			ClearExpiredFiles(path+file.Name()+"/", now)
		} else {
			targetFile := path + file.Name()
			if fi, err := os.Stat(targetFile); err == nil {
				fiStat := fi.Sys().(*syscall.Stat_t)
				// Use ctime fiStat.Ctim.Sec to mark the last check time
				pastSeconds := now.Unix() - int64(fiStat.Ctim.Sec)
				if pastSeconds >= 86400*7 {
					err = os.Remove(targetFile)
					if err != nil {
						utils.DebugPrintln("ClearExpiredFiles Remove", targetFile, err)
					}
				}
			}
		}
	}
}
