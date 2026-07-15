package tui

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	pkgapi "github.com/reloadlife/dnsd/pkg/api"
)

// Config for the TUI.
type Config struct {
	Client          *pkgapi.Client
	Endpoint        string
	RefreshInterval time.Duration
}

// Run starts the full-screen Bubble Tea program.
func Run(cfg Config) error {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = time.Second
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("tui requires an interactive terminal\nrun: dnsctl   # in a real shell")
	}
	m := newRootModel(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
