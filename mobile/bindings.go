package lndbindings

import (
	"fmt"
	"os"
	"runtime"

	flags "github.com/btcsuite/go-flags"
	"github.com/lightningnetwork/lnd/daemon"
)

func Start(appDir string) {
	// Use all processor cores.
	// TODO(roasbeef): remove this if required version # is > 1.6?
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Call the "real" main in a nested manner so the defers will properly
	// be executed in the case of a graceful shutdown.

	if err := daemon.LndMain(appDir); err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
