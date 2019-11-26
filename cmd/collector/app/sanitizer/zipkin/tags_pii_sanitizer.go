package zipkin

import (
	"bytes"
	"regexp"
	//"github.com/jaegertracing/jaeger/cmd/collector/app/sanitizer"
	zc "github.com/jaegertracing/jaeger/thrift-gen/zipkincore"
)

type tagsPiiSanitizer struct {

}

func NewTagsPiiSanitizer() Sanitizer {
	return &tagsPiiSanitizer{}
}

func (s *tagsPiiSanitizer) Sanitize(span *zc.Span) *zc.Span {
	//  "[0-9a-f]{24,64}", "_REDACTED_",
	if len(span.BinaryAnnotations) > 0 {
		for _, binAnno := range span.BinaryAnnotations {
			if binAnno.Key == "http.url" {
				checkRes := checkAndProcessPii(binAnno.Value)
				if !bytes.EqualFold(checkRes, binAnno.Value) {
					binAnno.Value = checkRes
				}
			}
		}
	}
	return span
}

// helper function to check if there is any pii related info
func checkAndProcessPii(s []byte) []byte {
	replStr := "/__REDACTED__"
	// possible userid/matchid
	re1 := regexp.MustCompile(`/[0-9a-fA-F]{24,56}`)
	check := re1.ReplaceAllString(string(s), replStr)
	return []byte(check)
}