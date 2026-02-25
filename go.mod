module github.com/crtsh/ctloglists

go 1.25.0

replace github.com/google/certificate-transparency-go => github.com/robstradling/certificate-transparency-go v0.0.0-20260225152442-9af2bdaa773a

require (
	github.com/google/certificate-transparency-go v1.3.2
	software.sslmate.com/src/certspotter v0.24.0
)

require (
	github.com/go-logr/logr v1.4.3 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
