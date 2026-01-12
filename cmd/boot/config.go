package boot

import (
	"fmt"
	"os"

	"github.com/Francesco99975/authpoc/internal/enums"
)

type Config struct {
	Port                 string
	Host                 string
	GoEnv                enums.Environment
	DSN                  string
	NTFY                 string
	NTFYToken            string
	URL                  string
	MetricSecret         string
	Prometheus           string
	ResendApiKey         string
	SessionAuthKey       string
	SessionEncryptionKey string
}

var Environment = &Config{}

func LoadEnvVariables() error {

	if !enums.IsEnvironmentValid(os.Getenv("GO_ENV")) {
		return fmt.Errorf("invalid environment variable: %s", os.Getenv("GO_ENV"))
	}

	Environment.Port = os.Getenv("PORT")
	Environment.Host = os.Getenv("HOST")
	Environment.GoEnv = enums.GetEnvironmentFromString(os.Getenv("GO_ENV"))
	Environment.DSN = os.Getenv("DSN")
	Environment.NTFY = os.Getenv("NTFY")
	Environment.NTFYToken = os.Getenv("NTFY_TOKEN")
	Environment.MetricSecret = os.Getenv("METRIC_SECRET")
	Environment.Prometheus = os.Getenv("PROMETHEUS")
	if Environment.GoEnv == enums.Environments.DEVELOPMENT {
		Environment.URL = fmt.Sprintf("http://%s:%s", Environment.Host, Environment.Port)
	} else {
		Environment.URL = fmt.Sprintf("https://%s", Environment.Host)
	}

	Environment.ResendApiKey = os.Getenv("RESEND_API_KEY")
	Environment.SessionAuthKey = os.Getenv("SESSION_AUTH_KEY")
	Environment.SessionEncryptionKey = os.Getenv("SESSION_ENCRYPTION_KEY")

	return nil
}
