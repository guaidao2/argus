// Command argus is a modern port scanner built for offensive security.
//
// Authors: guaidao2 & coolmoon. License: MIT.
package main

import (
	"os"

	"github.com/guaidao2/argus/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
