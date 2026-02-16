package main

import (
	"encoding/hex"
	"fmt"

	"github.com/crtsh/ctloglists"
)

func main() {
	if err := ctloglists.LoadAcceptedRoots(); err != nil {
		panic(err)
	}

	for logID, rootListHash := range ctloglists.LogAcceptedRootsMap {
		if ctloglists.AcceptedRootsMap[rootListHash] == nil {
			fmt.Printf("No accepted roots found for log with ID %s\n", hex.EncodeToString(logID[:]))
		} else {
			fmt.Printf("\n%s (%s)\n", hex.EncodeToString(logID[:]), hex.EncodeToString(rootListHash[:]))
			for _, cert := range ctloglists.AcceptedRootsMap[rootListHash].RawCertificates() {
				fmt.Printf("  %s\n", cert.Subject.String())
			}
		}
	}
}
