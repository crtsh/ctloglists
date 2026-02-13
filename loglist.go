package ctloglists

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"strings"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

const acceptedRootsDir = "files/acceptedroots"
const gstaticV3AllLogsListFilename = "files/gstatic/v3/all_logs_list.json"
const appleCurrentLogListFilename = "files/apple/current_log_list.json"
const crtshV3AllLogsListFilename = "files/crtsh/v3/all_logs_list.json"
const mozillaV3KnownLogsListFilename = "files/mozilla/v3/known_logs_list.json"
const bimiV3ApprovedLogsListFilename = "files/bimi/v3/approved_logs_list.json"
const logMimicsListFilename = "files/mimics/log_mimics_list.json"

//go:embed files/*
var files embed.FS
var GstaticV3All, AppleCurrent, CrtshV3All, MozillaV3Known, BimiV3Approved, LogMimics *loglist3.LogList
var LogSignatureVerifierMap map[[sha256.Size]byte]*ctgo.SignatureVerifier
var TemporalIntervalMap map[[sha256.Size]byte]*loglist3.TemporalInterval
var AcceptedRootsMap map[[sha256.Size]byte]*x509util.PEMCertPool
var LogAcceptedRootsMap map[[sha256.Size]byte][sha256.Size]byte

func init() {
	LogSignatureVerifierMap = make(map[[sha256.Size]byte]*ctgo.SignatureVerifier)
	TemporalIntervalMap = make(map[[sha256.Size]byte]*loglist3.TemporalInterval)
	AcceptedRootsMap = make(map[[sha256.Size]byte]*x509util.PEMCertPool)
	LogAcceptedRootsMap = make(map[[sha256.Size]byte][sha256.Size]byte)
}

func Load() error {
	var err error

	if err = loadAcceptedRoots(); err == nil {
		if GstaticV3All, err = loadLogList(gstaticV3AllLogsListFilename); err == nil {
			if AppleCurrent, err = loadLogList(appleCurrentLogListFilename); err == nil {
				if CrtshV3All, err = loadLogList(crtshV3AllLogsListFilename); err == nil {
					if MozillaV3Known, err = loadLogList(mozillaV3KnownLogsListFilename); err == nil {
						if BimiV3Approved, err = loadLogList(bimiV3ApprovedLogsListFilename); err == nil {
							LogMimics, err = loadLogList(logMimicsListFilename)
						}
					}
				}
			}
		}
	}

	return err
}

func loadAcceptedRoots() error {
	if dirEntry, err := files.ReadDir(acceptedRootsDir); err != nil {
		return err
	} else {
		// Load the Accepted Roots lists.
		for _, file := range dirEntry {
			if strings.HasPrefix(file.Name(), "roots_") {
				decodedHash, err := hex.DecodeString(file.Name()[6:70])
				if err != nil {
					return err
				}
				var rootsListHash [sha256.Size]byte
				copy(rootsListHash[:], decodedHash)
				AcceptedRootsMap[rootsListHash] = x509util.NewPEMCertPool()
				var pemData []byte
				if pemData, err = files.ReadFile(acceptedRootsDir + "/" + file.Name()); err != nil {
					return err
				}
				if !AcceptedRootsMap[rootsListHash].AppendCertsFromPEM(pemData) {
					return fmt.Errorf("failed to parse PEM data from %s", file.Name())
				}
			}
		}
		// Load the mapping of log IDs to Accepted Roots list hashes.
		for _, file := range dirEntry {
			if strings.HasPrefix(file.Name(), "log_") {
				decodedHash, err := hex.DecodeString(file.Name()[4:68])
				if err != nil {
					return err
				}
				var logID [sha256.Size]byte
				copy(logID[:], decodedHash)
				if data, err := files.ReadFile(acceptedRootsDir + "/" + file.Name()); err == nil {
					var decoded []byte
					if decoded, err = hex.DecodeString(string(data)); err != nil {
						return err
					}
					var rootsListHash [sha256.Size]byte
					copy(rootsListHash[:], decoded)
					LogAcceptedRootsMap[logID] = rootsListHash
				} else {
					return err
				}
			}
		}
	}
	return nil
}

func loadLogList(logListFilename string) (*loglist3.LogList, error) {
	var logList *loglist3.LogList
	var err error
	if data, err := files.ReadFile(logListFilename); err == nil {
		if logList, err = loglist3.NewFromJSON(data); err == nil {
			err = addSignatureVerifiersForLogList(logList)
		}
	}
	return logList, err
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
