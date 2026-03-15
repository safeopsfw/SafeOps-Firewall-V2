package main

import (
	"os/exec"
	"syscall"
)

func cmdStart(exePath string) *exec.Cmd {
	cmd := exec.Command(exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    false,
		CreationFlags: 0,
	}
	return cmd
}
