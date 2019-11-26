package zipkin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jaegertracing/jaeger/thrift-gen/zipkincore"
)

func TestTagsPiiSanitizer(t *testing.T) {
	sanitizer := NewTagsPiiSanitizer()
	tests := []struct {
		binAnn       *zipkincore.BinaryAnnotation
		expectedRes []byte
	}{
		{
			&zipkincore.BinaryAnnotation{Key: "http.url", Value: []byte("http://call.service.a/user/health"), AnnotationType: zipkincore.AnnotationType_STRING},
			[]byte("http://call.service.a/user/health"),
		},
		{
			&zipkincore.BinaryAnnotation{Key: "http.url", Value: []byte("http://call.service.a/user/aaaaaabbbbbbccccccdddddd/health"), AnnotationType: zipkincore.AnnotationType_STRING},
			[]byte("http://call.service.a/user/__REDACTED__/health"),
		},
		{
			&zipkincore.BinaryAnnotation{Key: "http.url", Value: []byte("http://call.service.a/user/aaaaaabbbbbbccccc8888cdddddd/health"), AnnotationType: zipkincore.AnnotationType_STRING},
			[]byte("http://call.service.a/user/__REDACTED__/health"),
		},
	}

	for _, test := range tests {
		span := &zipkincore.Span{
			BinaryAnnotations:[]*zipkincore.BinaryAnnotation{test.binAnn},
		}
		sanitized := sanitizer.Sanitize(span)
		assert.Equal(t, test.expectedRes, sanitized.BinaryAnnotations[0].Value)
	}
}