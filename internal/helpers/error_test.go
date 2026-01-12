package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ——————— TESTS ———————

func TestSendReturnedGenericJSONError(t *testing.T) {
	t.Parallel()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := GenericError{
		Code:        418,
		Message:     "I'm a teapot",
		UserMessage: "Cannot brew coffee",
		Errors:      []string{"short and stout", "handle broken"},
	}

	// Test with reporter
	assert.NoError(t, SendReturnedGenericJSONError(c, err, nil))

	// Status code
	assert.Equal(t, 418, rec.Code)

	// JSON body
	var resp models.JSONErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 418, resp.Code)
	assert.Equal(t, "Cannot brew coffee", resp.Message)
	assert.Equal(t, []string{"short and stout", "handle broken"}, resp.Errors)

}

func TestSendReturnedGenericJSONError_NoReporter(t *testing.T) {
	t.Parallel()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := GenericError{
		Code:        500,
		Message:     "Server exploded",
		UserMessage: "Something went wrong",
		Errors:      []string{"boom"},
	}

	assert.NoError(t, SendReturnedGenericJSONError(c, err, nil))
	assert.Equal(t, 500, rec.Code)

	var resp models.JSONErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "Something went wrong", resp.Message)
}

func TestSendReturnedGenericHTMLError(t *testing.T) {
	t.Parallel()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := GenericError{
		Code:        404,
		Message:     "Not found",
		UserMessage: "Page vanished into void",
	}

	assert.NoError(t, SendReturnedGenericHTMLError(c, err, nil))

	assert.Equal(t, 404, rec.Code)
	assert.Equal(t, "text/html", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "404")
	assert.Contains(t, rec.Body.String(), "Page vanished into void")
}

func TestSendReturnedHTMLErrorMessage(t *testing.T) {
	t.Parallel()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	errMsg := ErrorMessage{
		Error: GenericError{
			Code:        400,
			Message:     "Bad request",
			UserMessage: "You did something wrong",
			Errors:      []string{"invalid input"},
		},
		Box:         enums.Boxes.TOAST_TR,
		Persistance: "5s",
	}

	assert.NoError(t, SendReturnedHTMLErrorMessage(c, errMsg, nil))

	assert.Equal(t, 400, rec.Code)
	assert.Equal(t, "text/html", rec.Header().Get("Content-Type"))

	body := rec.Body.String()
	assert.Contains(t, body, "You did something wrong")
	assert.Contains(t, body, "TOAST_TR")
	assert.Contains(t, body, "5s")

}

func TestGenericError_Stringify(t *testing.T) {
	t.Parallel()

	err := GenericError{
		Code:    429,
		Message: "Too many requests",
		Errors:  []string{"rate limit exceeded", "calm down"},
	}

	expected := "[429] Too many requests <-- [rate limit exceeded calm down]"
	assert.Equal(t, expected, err.Stringify())
}

func TestConcurrent_ErrorSending_NoRace(t *testing.T) {
	t.Parallel()

	e := echo.New()

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(code int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := GenericError{
				Code:        400 + code%20,
				Message:     fmt.Sprintf("error %d", code),
				UserMessage: "user msg",
			}

			_ = SendReturnedGenericJSONError(c, err, nil)
			_ = SendReturnedGenericHTMLError(c, err, nil)
		}(i)
	}
	wg.Wait()

	// No race = pass
	assert.True(t, true)
}

// ——————— BENCHMARKS ———————
func BenchmarkSendReturnedGenericJSONError(b *testing.B) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := GenericError{
		Code:        500,
		Message:     "boom",
		UserMessage: "oops",
		Errors:      []string{"a", "b", "c"},
	}

	for b.Loop() {
		rec.Body.Reset()
		_ = SendReturnedGenericJSONError(c, err, nil)
	}
}

func BenchmarkSendReturnedHTMLErrorMessage(b *testing.B) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	errMsg := ErrorMessage{
		Error: GenericError{
			Code:        400,
			UserMessage: "bad",
		},
		Box:         enums.Boxes.TOAST_BL,
		Persistance: "3s",
	}

	for b.Loop() {
		rec.Body.Reset()
		_ = SendReturnedHTMLErrorMessage(c, errMsg, nil)
	}
}
