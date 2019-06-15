package log

import (
	"fmt"
)

var (
	Verbose bool
)

func Init(verbose bool) error {
	Verbose = verbose
	return nil
}

func Debug(format string, v ...interface{}) {
	if Verbose {
		fmt.Println(fmt.Sprintf(format, v...))
	}
}

func Println(format string, v ...interface{}) {
	fmt.Println(fmt.Sprintf(format, v...))
}
