package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/crtsh/ctloglists"

	"github.com/google/certificate-transparency-go/loglist3"
)

func main() {
	// Load log lists.
	if err := ctloglists.LoadLogLists(); err != nil {
		panic(err)
	}

	// Define allowed log lists.
	logListNames := map[string]*loglist3.LogList{
		"gstatic-all":   ctloglists.GstaticV3All,
		"apple-current": ctloglists.AppleCurrent,
		"crtsh-all":     ctloglists.CrtshV3All,
		"crtsh-active":  ctloglists.CrtshV3Active,
		"mozilla-known": ctloglists.MozillaV3Known,
		"bimi-approved": ctloglists.BimiV3Approved,
		"log-mimics":    ctloglists.LogMimics,
	}

	// Use two required positional arguments instead of flags.
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <loglist1> <loglist2>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Allowed values: ")
		for k := range logListNames {
			fmt.Fprintf(os.Stderr, "%s ", k)
		}
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}
	arg1 := os.Args[1]
	arg2 := os.Args[2]
	ll1, ok1 := logListNames[arg1]
	ll2, ok2 := logListNames[arg2]
	if !ok1 || !ok2 {
		fmt.Fprintf(os.Stderr, "Error: unknown log list name(s).\n")
		fmt.Fprintf(os.Stderr, "Allowed values: ")
		for k := range logListNames {
			fmt.Fprintf(os.Stderr, "%s ", k)
		}
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}

	fmt.Printf("Present in %s but not in %s:\n", arg1, arg2)
	for _, operator := range ll1.Operators {
		for _, log1 := range operator.Logs {
			if log2 := ll2.FindLogByKey(log1.Key); log2 == nil {
				logType := ""
				if log1.Type != "" {
					logType = fmt.Sprintf("[%s] ", log1.Type)
				}
				fmt.Printf("- %s%s; %s\n", logType, log1.URL, base64.StdEncoding.EncodeToString(log1.LogID))
			}
		}
		for _, log1 := range operator.TiledLogs {
			if log2 := ll2.FindTiledLogByKey(log1.Key); log2 == nil {
				logType := ""
				if log1.Type != "" {
					logType = fmt.Sprintf("[%s] ", log1.Type)
				}
				fmt.Printf("- %s%s; %s\n", logType, log1.SubmissionURL, base64.StdEncoding.EncodeToString(log1.LogID))
			}
		}
	}

	fmt.Printf("\nPresent in %s but not in %s:\n", arg2, arg1)
	for _, operator := range ll2.Operators {
		for _, log2 := range operator.Logs {
			if log1 := ll1.FindLogByKey(log2.Key); log1 == nil {
				logType := ""
				if log2.Type != "" {
					logType = fmt.Sprintf("[%s] ", log2.Type)
				}
				fmt.Printf("- %s%s; %s\n", logType, log2.URL, base64.StdEncoding.EncodeToString(log2.LogID))
			}
		}
		for _, log2 := range operator.TiledLogs {
			if log1 := ll1.FindTiledLogByKey(log2.Key); log1 == nil {
				logType := ""
				if log2.Type != "" {
					logType = fmt.Sprintf("[%s] ", log2.Type)
				}
				fmt.Printf("- %s%s; %s\n", logType, log2.SubmissionURL, base64.StdEncoding.EncodeToString(log2.LogID))
			}
		}
	}

	fmt.Printf("\nState differences between %s and %s:\n", arg1, arg2)
	for _, operator := range ll1.Operators {
		for _, log1 := range operator.Logs {
			log2 := ll2.FindLogByKey(log1.Key)
			if log2 != nil {
				logType := ""
				if log1.Type != "" {
					logType = fmt.Sprintf("[%s] ", log1.Type)
				}
				state1 := log1.State.LogStatus().String()
				state2 := log2.State.LogStatus().String()
				if state1 != state2 {
					fmt.Printf("- %s%s: %s vs %s\n", logType, log1.URL, strings.Replace(state1, "LogStatus", "", -1), strings.Replace(state2, "LogStatus", "", -1))
				}
			}
		}
		for _, log1 := range operator.TiledLogs {
			log2 := ll2.FindTiledLogByKey(log1.Key)
			if log2 != nil {
				logType := ""
				if log1.Type != "" {
					logType = fmt.Sprintf("[%s] ", log1.Type)
				}
				state1 := log1.State.LogStatus().String()
				state2 := log2.State.LogStatus().String()
				if state1 != state2 {
					fmt.Printf("- %s%s: %s vs %s\n", logType, log1.SubmissionURL, strings.Replace(state1, "LogStatus", "", -1), strings.Replace(state2, "LogStatus", "", -1))
				}
			}
		}
	}

	fmt.Printf("\nTemporal Period differences between %s and %s:\n", arg1, arg2)
	for _, operator := range ll1.Operators {
		for _, log1 := range operator.Logs {
			log2 := ll2.FindLogByKey(log1.Key)
			if log2 != nil {
				logType := ""
				if log1.Type != "" {
					logType = fmt.Sprintf("[%s] ", log1.Type)
				}
				period1 := log1.TemporalInterval
				period2 := log2.TemporalInterval
				if !temporalIntervalsEqual(period1, period2) {
					fmt.Printf("- %s%s: %s vs %s\n", logType, log1.URL, temporalIntervalString(period1), temporalIntervalString(period2))
				}
			}
		}
		for _, log1 := range operator.TiledLogs {
			log2 := ll2.FindTiledLogByKey(log1.Key)
			if log2 != nil {
				logType := ""
				if log1.Type != "" {
					logType = fmt.Sprintf("[%s] ", log1.Type)
				}
				period1 := log1.TemporalInterval
				period2 := log2.TemporalInterval
				if !temporalIntervalsEqual(period1, period2) {
					fmt.Printf("- %s%s: %s vs %s\n", logType, log1.SubmissionURL, temporalIntervalString(period1), temporalIntervalString(period2))
				}
			}
		}
	}
}

func temporalIntervalsEqual(a, b *loglist3.TemporalInterval) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.StartInclusive.Equal(b.StartInclusive) && a.EndExclusive.Equal(b.EndExclusive)
}

func temporalIntervalString(ti *loglist3.TemporalInterval) string {
	if ti == nil {
		return "<none>"
	}
	return fmt.Sprintf("[%s, %s)", ti.StartInclusive.Format("2006-01-02T15:04:05Z07:00"), ti.EndExclusive.Format("2006-01-02T15:04:05Z07:00"))
}
