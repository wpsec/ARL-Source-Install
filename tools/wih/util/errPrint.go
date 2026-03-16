package util

import (
	"fmt"
	"os"
	"strings"
	"time"
	"wih/global"

	"github.com/gookit/color"
)

// ErrPrint 输出错误日志。
// 行为：
// - debug 模式打印彩色日志
// - 配置了 --log-file 时会落盘
func ErrPrint(err error) {
	if err == nil {
		return
	}

	if global.Debug || strings.EqualFold(global.LogLevel, "debug") {
		if global.DisableColor {
			fmt.Println(err)
		} else {
			color.Errorln(err)
		}
	}

	logPath := strings.TrimSpace(global.LogFile)
	if logPath == "" || logPath == "-" {
		return
	}

	line := fmt.Sprintf("[%s] [error] %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
	file, openErr := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if openErr != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(line)
}
