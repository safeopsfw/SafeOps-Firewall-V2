package main

import (
	"os"
	"path/filepath"

	"github.com/energye/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// initSystray sets up the system tray icon and menu.
func (a *App) initSystray() {
	systray.Run(func() {
		iconData := loadTrayIcon()
		if iconData != nil {
			systray.SetIcon(iconData)
		}
		systray.SetTitle("SafeOps")
		systray.SetTooltip("SafeOps Firewall - Running")

		mShow := systray.AddMenuItem("Show SafeOps", "Show the main window")
		mShow.Click(func() {
			if a.ctx != nil {
				wailsruntime.WindowShow(a.ctx)
			}
		})

		mHide := systray.AddMenuItem("Hide SafeOps", "Minimize to tray")
		mHide.Click(func() {
			if a.ctx != nil {
				wailsruntime.WindowHide(a.ctx)
			}
		})

		systray.AddSeparator()

		mQuit := systray.AddMenuItem("Quit SafeOps", "Stop all services and exit")
		mQuit.Click(func() {
			a.QuitApp()
		})

		// Left-click on tray icon shows window
		systray.SetOnClick(func(menu systray.IMenu) {
			if a.ctx != nil {
				wailsruntime.WindowShow(a.ctx)
			}
		})
		systray.SetOnDClick(func(menu systray.IMenu) {
			if a.ctx != nil {
				wailsruntime.WindowShow(a.ctx)
			}
		})
	}, nil)
}

// QuitApp stops all services and exits the application completely.
func (a *App) QuitApp() {
	a.StopAll()
	systray.Quit()
	os.Exit(0)
}

// ShowWindow exposes window show to frontend.
func (a *App) ShowWindow() {
	if a.ctx != nil {
		wailsruntime.WindowShow(a.ctx)
	}
}

// HideWindow exposes window hide to frontend.
func (a *App) HideWindow() {
	if a.ctx != nil {
		wailsruntime.WindowHide(a.ctx)
	}
}

// loadTrayIcon loads icon.ico for the system tray.
func loadTrayIcon() []byte {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		paths := []string{
			filepath.Join(dir, "icon.ico"),
			filepath.Join(dir, "build", "windows", "icon.ico"),
		}
		for _, p := range paths {
			if data, err := os.ReadFile(p); err == nil {
				return data
			}
		}
	}
	// Fallback: relative paths for dev
	for _, p := range []string{"build/windows/icon.ico", "icon.ico"} {
		if data, err := os.ReadFile(p); err == nil {
			return data
		}
	}
	return nil
}
