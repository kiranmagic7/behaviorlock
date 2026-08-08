package main

import (
	"os"

	"github.com/kiranmagic7/behaviorlock/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
