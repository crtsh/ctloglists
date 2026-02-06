package ctloglists

import (
	"crypto/sha256"
	"embed"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

const gstaticV3AllLogsListFilename = "files/gstatic/v3/all_logs_list.json"
const appleCurrentLogListFilename = "files/apple/current_log_list.json"
const crtshV3AllLogsListFilename = "files/crtsh/v3/all_logs_list.json"
const mozillaV3KnownLogsListFilename = "files/mozilla/v3/known_logs_list.json"
const bimiV3ApprovedLogsListFilename = "files/bimi/v3/approved_logs_list.json"

//go:embed files/*
var files embed.FS
var GstaticV3All, AppleCurrent, CrtshV3All, MozillaV3Known, BimiV3Approved *loglist3.LogList
var LogSignatureVerifierMap map[[sha256.Size]byte]*ctgo.SignatureVerifier
var TemporalIntervalMap map[[sha256.Size]byte]*loglist3.TemporalInterval

func init() {
	LogSignatureVerifierMap = make(map[[sha256.Size]byte]*ctgo.SignatureVerifier)
	TemporalIntervalMap = make(map[[sha256.Size]byte]*loglist3.TemporalInterval)
}

func Load() error {
	var err error

	if GstaticV3All, err = loadLogList(gstaticV3AllLogsListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(GstaticV3All); err != nil {
		return err
	}

	if AppleCurrent, err = loadLogList(appleCurrentLogListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(AppleCurrent); err != nil {
		return err
	}

	if CrtshV3All, err = loadLogList(crtshV3AllLogsListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(CrtshV3All); err != nil {
		return err
	}

	if MozillaV3Known, err = loadLogList(mozillaV3KnownLogsListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(MozillaV3Known); err != nil {
		return err
	}

	if BimiV3Approved, err = loadLogList(bimiV3ApprovedLogsListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(BimiV3Approved); err != nil {
		return err
	}

	return nil
}

func loadLogList(logListFilename string) (*loglist3.LogList, error) {
	if data, err := files.ReadFile(logListFilename); err != nil {
		return nil, err
	} else {
		return loglist3.NewFromJSON(data)
	}
}

func populateMaps(logPublicKey []byte, ti *loglist3.TemporalInterval) error {
	publicKey, err := x509.ParsePKIXPublicKey(logPublicKey)
	if err != nil {
		return err
	}

	logID := sha256.Sum256(logPublicKey)
	if LogSignatureVerifierMap[logID] == nil {
		sv, err := ctgo.NewSignatureVerifier(publicKey)
		if err != nil {
			return err
		}
		LogSignatureVerifierMap[logID] = sv
	}

	if ti != nil {
		if TemporalIntervalMap[logID] == nil {
			TemporalIntervalMap[logID] = ti
		} else {
			if ti.StartInclusive.After(TemporalIntervalMap[logID].StartInclusive) {
				TemporalIntervalMap[logID].StartInclusive = ti.StartInclusive
			}
			if ti.EndExclusive.Before(TemporalIntervalMap[logID].EndExclusive) {
				TemporalIntervalMap[logID].EndExclusive = ti.EndExclusive
			}
		}
	}

	return nil
}

func addSignatureVerifiersForLogList(logList *loglist3.LogList) error {
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if err := populateMaps(log.Key, log.TemporalInterval); err != nil {
				return err
			}
		}
		for _, tiledLog := range operator.TiledLogs {
			if err := populateMaps(tiledLog.Key, tiledLog.TemporalInterval); err != nil {
				return err
			}
		}
	}

	return nil
}
