package util

import (
	"fmt"
	"os"
	"strings"
	"time"
	"wih/global"

	"github.com/gookit/color"
)

// WarnPrint 输出提醒日志。
func WarnPrint(message string) {
	text := strings.TrimSpace(message)
	if text == "" {
		return
	}

	if !strings.EqualFold(global.LogLevel, "zero") {
		if global.DisableColor {
			fmt.Println(text)
		} else {
			color.Warnln(text)
		}
	}

	logPath := strings.TrimSpace(global.LogFile)
	if logPath == "" || logPath == "-" {
		return
	}

	line := fmt.Sprintf("[%s] [warn] %s\n", time.Now().Format("2006-01-02 15:04:05"), text)
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(line)
}
