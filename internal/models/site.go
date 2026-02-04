package models

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
)

type Organization struct {
	Context      string         `json:"@context"`
	Type         string         `json:"@type"`
	Name         string         `json:"name"`
	Url          string         `json:"url"`
	Logo         string         `json:"logo"`
	ContactPoint []ContactPoint `json:"contactPoint"`
}

type ContactPoint struct {
	Type        string `json:"@type"`
	Telephone   string `json:"telephone"`
	ContactType string `json:"contactType"`
}

type SEO struct {
	Description string
	Keywords    string
	Author      string
	Canonical   string
}
type Site struct {
	AppName      string
	Title        string
	Metatags     SEO
	Year         int
	CSRF         string
	Nonce        string
	Organization Organization
	Styles       []string
	SeoScripts   []string
	PageScripts  []string
	JSFile       string
	JSIntegrity  string
	CSSFile      string
	CSSIntegrity string
}

func GetDefaultSite(title string, r *http.Request) Site {
	jsFile, jsIntegrity := GetJS()

	cssFile, cssIntegrity := GetCSS()

	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}

	return Site{
		AppName:  "AUTH POC",
		Title:    title,
		Metatags: SEO{Description: "App", Keywords: "tool", Author: "kalairen", Canonical: fmt.Sprintf("%s://%s%s", protocol, r.Host, r.URL.Path)},
		Year:     time.Now().Year(),
		Organization: Organization{
			Context:      "https://schema.org",
			Type:         "Organization",
			Name:         "GoApp",
			Url:          boot.Environment.URL,
			Logo:         fmt.Sprintf("%s/assets/images/pwa-512x512.png", boot.Environment.URL),
			ContactPoint: []ContactPoint{{Type: "Person", Telephone: "+1-202-555-0144", ContactType: "customer service"}},
		},
		JSFile:       jsFile,
		JSIntegrity:  jsIntegrity,
		CSSFile:      cssFile,
		CSSIntegrity: cssIntegrity,
	}
}
