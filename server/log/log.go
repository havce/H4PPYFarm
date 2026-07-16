package log

import (
	"fmt"
	"time"
)

func Info(a ...any) {
	fmt.Printf("[%s] [INFO] %v\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(a...))
}

func Warn(a ...any) {
	fmt.Printf("[%s] [WARN] %v\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(a...))
}

func Error(a ...any) {
	fmt.Printf("[%s] [Error] %v\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(a...))
}

func Fatal(a ...any) {
	fmt.Printf("[%s] [FATAL] %v\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(a...))
	panic(a)
}
