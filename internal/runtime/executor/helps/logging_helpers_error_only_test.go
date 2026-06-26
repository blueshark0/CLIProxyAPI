package helps

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
)

// newErrorOnlyContext builds a context carrying a gin.Context that is flagged for
// error-only logging when errorOnly is true.
func newErrorOnlyContext(errorOnly bool) (context.Context, *gin.Context) {
	gin.SetMode(gin.TestMode)
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	if errorOnly {
		ginCtx.Set(apiErrorOnlyLogKey, true)
	}
	ctx := context.WithValue(logging.WithResponseHeadersHolder(context.Background()), "gin", ginCtx)
	return ctx, ginCtx
}

func ginBytes(t *testing.T, ginCtx *gin.Context, key string) []byte {
	t.Helper()
	value, exists := ginCtx.Get(key)
	if !exists {
		return nil
	}
	data, ok := value.([]byte)
	if !ok {
		t.Fatalf("context key %q is not []byte", key)
	}
	return data
}

// In error-only mode (RequestLog disabled), the upstream request must still be recorded so
// a forced error log can render the API REQUEST section.
func TestRecordAPIRequestErrorOnlyCapturesRequest(t *testing.T) {
	ctx, ginCtx := newErrorOnlyContext(true)

	RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{
		URL:    "https://upstream.example/v1/messages",
		Method: http.MethodPost,
		Body:   []byte(`{"model":"claude"}`),
	})

	got := ginBytes(t, ginCtx, apiRequestKey)
	if len(got) == 0 {
		t.Fatal("API_REQUEST is empty, want recorded upstream request")
	}
	if !bytes.Contains(got, []byte("=== API REQUEST 1 ===")) {
		t.Fatalf("API_REQUEST missing section header: %s", got)
	}
	if !bytes.Contains(got, []byte("https://upstream.example/v1/messages")) {
		t.Fatalf("API_REQUEST missing upstream URL: %s", got)
	}
}

// An error response (non-2xx status + body) must be captured in error-only mode.
func TestAppendAPIResponseChunkErrorOnlyCapturesErrorBody(t *testing.T) {
	ctx, ginCtx := newErrorOnlyContext(true)
	cfg := &config.Config{}

	RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: "https://upstream.example", Method: http.MethodPost})
	RecordAPIResponseMetadata(ctx, cfg, http.StatusInternalServerError, http.Header{})
	AppendAPIResponseChunk(ctx, cfg, []byte(`{"error":{"message":"boom"}}`))

	got := ginBytes(t, ginCtx, apiResponseKey)
	if !bytes.Contains(got, []byte("boom")) {
		t.Fatalf("API_RESPONSE missing error body: %s", got)
	}
}

// Without the error-only flag and with RequestLog disabled, nothing is recorded (old behavior).
func TestRecordAPIRequestNoFlagRecordsNothing(t *testing.T) {
	ctx, ginCtx := newErrorOnlyContext(false)

	RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{URL: "https://upstream.example", Method: http.MethodPost})

	if got := ginBytes(t, ginCtx, apiRequestKey); len(got) != 0 {
		t.Fatalf("API_REQUEST = %q, want empty", got)
	}
}

// A successful streaming response body must not be buffered in error-only mode, to preserve
// the low-memory design. Bounded status/header metadata may still be recorded (it is dropped
// at Finalize for successful requests), but the unbounded streamed body must be skipped.
func TestAppendAPIResponseChunkErrorOnlySkipsSuccessfulStream(t *testing.T) {
	ctx, ginCtx := newErrorOnlyContext(true)
	cfg := &config.Config{}

	RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: "https://upstream.example", Method: http.MethodPost})
	RecordAPIResponseMetadata(ctx, cfg, http.StatusOK, http.Header{})
	for i := 0; i < 3; i++ {
		AppendAPIResponseChunk(ctx, cfg, []byte("data: {\"delta\":\"chunk\"}"))
	}

	got := ginBytes(t, ginCtx, apiResponseKey)
	if bytes.Contains(got, []byte("Body:")) || bytes.Contains(got, []byte("chunk")) {
		t.Fatalf("API_RESPONSE buffered successful stream body: %s", got)
	}
}
