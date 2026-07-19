package log

import (
	"fmt"
	"strings"
	"time"
)

func render(a ...any) string {
	if len(a) > 1 {
		if f, ok := a[0].(string); ok && strings.Contains(f, "%") {
			return fmt.Sprintf(f, a[1:]...)
		}
	}
	return fmt.Sprint(a...)
}

func logf(level string, a ...any) {
	fmt.Printf("[%s] [%s] %v\n", time.Now().Format("2006-01-02 15:04:05"), level, render(a...))
}

func Info(a ...any) {
	logf("INFO", a...)
}

func Warn(a ...any) {
	logf("WARN", a...)
}

func Error(a ...any) {
	logf("ERROR", a...)
}

func Ensure(check bool, a ...any) {
	if !check {
		logf("FATAL", a...)
		panic(a)
	}
}

func Fatal(a ...any) {
	logf("FATAL", a...)
	panic(a)
}
