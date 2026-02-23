package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crtsh/ctloglists"

	"github.com/google/certificate-transparency-go/loglist3"
)

type LogInfo struct {
	LogID         string
	AcceptedRoots string
}

var (
	mutex      sync.Mutex
	wg         sync.WaitGroup
	httpClient *http.Client
	logInfo    map[string]*LogInfo
)

func init() {
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	logInfo = make(map[string]*LogInfo)
}

func main() {
	if err := ctloglists.LoadLogLists(); err != nil {
		panic(err)
	}

	// Get the full list of unique log base URLs.
	loadLogBaseURLs(ctloglists.GstaticV3All)
	loadLogBaseURLs(ctloglists.AppleCurrent)
	loadLogBaseURLs(ctloglists.CrtshV3All)
	// ctloglists.MozillaV3Known doesn't include the log base URLs, and it's expected to track Chrome's log list anyway.
	loadLogBaseURLs(ctloglists.BimiV3Approved)

	// Download the accepted roots from each log's get-roots endpoint in parallel.
	for li := range logInfo {
		wg.Add(1)
		go downloadRoots(li)
	}
	wg.Wait()

	for logBaseURL, li := range logInfo {
		fmt.Printf("Accepted roots from %s (Log ID: %s): %d bytes\n", logBaseURL, li.LogID, len(li.AcceptedRoots))
		writeRootsToFile(logBaseURL, li)
	}

	fmt.Printf("\nDownload complete. Retrieved accepted roots from %d logs.\n", len(logInfo))
}

func loadLogBaseURLs(logList *loglist3.LogList) {
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if (log.State != nil && (log.State.Usable != nil || log.State.Qualified != nil)) || !strings.HasPrefix(log.Type, "prod") {
				logInfo[log.URL] = &LogInfo{LogID: hex.EncodeToString(log.LogID), AcceptedRoots: ""}
			}
		}
		for _, tiledLog := range operator.TiledLogs {
			if (tiledLog.State != nil && (tiledLog.State.Usable != nil || tiledLog.State.Qualified != nil)) || !strings.HasPrefix(tiledLog.Type, "prod") {
				logInfo[tiledLog.SubmissionURL] = &LogInfo{LogID: hex.EncodeToString(tiledLog.LogID), AcceptedRoots: ""}
			}
		}
	}
}

func downloadRoots(baseURL string) {
	defer wg.Done()

	// Construct the get-roots URL
	url := strings.TrimSuffix(baseURL, "/") + "/ct/v1/get-roots"

	const maxAttempts = 5
	const retryDelay = 10 * time.Second
	var resp *http.Response
	var body []byte
	var err error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Make the HTTP request
		resp, err = httpClient.Get(url)
		if err != nil {
			fmt.Printf("Error fetching %s (attempt %d/%d): %v\n", url, attempt, maxAttempts, err)
			goto retry
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			fmt.Printf("Non-OK status for %s (attempt %d/%d): %d\n", url, attempt, maxAttempts, resp.StatusCode)
			goto retry
		}

		// Read the response body
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading response from %s (attempt %d/%d): %v\n", url, attempt, maxAttempts, err)
			goto retry
		}

		// Store in map (thread-safe)
		mutex.Lock()
		logInfo[baseURL].AcceptedRoots = string(body)
		mutex.Unlock()

		fmt.Printf("Successfully downloaded accepted roots from %s/ct/v1/get-roots\n", url)
		return

	retry:
		if attempt < maxAttempts {
			time.Sleep(retryDelay)
			continue
		}
		fmt.Printf("Failed to download accepted roots from %s after %d attempts\n", url, maxAttempts)
		return
	}
}

func writeRootsToFile(baseURL string, li *LogInfo) {
	// Decode the JSON response
	var response struct {
		Certificates []string `json:"certificates"`
	}
	err := json.Unmarshal([]byte(li.AcceptedRoots), &response)
	if err != nil {
		fmt.Printf("Error decoding JSON from %s: %v\n", baseURL, err)
		return
	}

	// Sort certificates alphanumerically
	sort.Strings(response.Certificates)

	// Base64 decode each certificate and encode as PEM
	var pemData strings.Builder
	for i, b64Cert := range response.Certificates {
		// Base64 decode the certificate
		certDER, err := base64.StdEncoding.DecodeString(b64Cert)
		if err != nil {
			fmt.Printf("Error decoding certificate %d from %s: %v\n", i, baseURL, err)
			continue
		}

		// Encode as PEM
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}
		pem.Encode(&pemData, pemBlock)
	}

	// Write the PEM-encoded certificate list to a file. This step deduplicates lists shared by multiple logs/shards.
	sha256PEMData := sha256.Sum256([]byte(pemData.String()))
	filename1 := "roots_" + hex.EncodeToString(sha256PEMData[:]) + ".pem"
	if err = os.WriteFile(filename1, []byte(pemData.String()), 0644); err != nil {
		fmt.Printf("Error writing file %s: %v\n", filename1, err)
		return
	}

	// Write the hash of the Accepted Roots list to a file.
	// (A symlink would be tidier, but unfortunately go:embed doesn't support them).
	filename2 := "log_" + li.LogID + ".txt"
	if err = os.WriteFile(filename2, []byte(hex.EncodeToString(sha256PEMData[:])), 0644); err != nil {
		fmt.Printf("Error writing file %s: %v\n", filename2, err)
		return
	}

	fmt.Printf("Wrote %s and %s\n", filename1, filename2)
}
