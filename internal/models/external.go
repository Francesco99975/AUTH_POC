package models

import (
	"encoding/json"
	"fmt"
	"time"
)

type GithubStatusResponse struct {
	Page struct {
		Name string `json:"name"`
	} `json:"page"`
	Components []GithubComponent `json:"components"`
	Status     GithubStatus      `json:"status"`
}

type GithubStatus struct {
	Indicator   string `json:"indicator"`
	Description string `json:"description"`
}

type GithubComponent struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Position           int       `json:"position"`
	Description        string    `json:"description"`
	Showcase           bool      `json:"showcase"`
	StartDate          *string   `json:"start_date"` // nullable
	GroupID            *string   `json:"group_id"`   // nullable
	PageID             string    `json:"page_id"`
	Group              bool      `json:"group"`
	OnlyShowIfDegraded bool      `json:"only_show_if_degraded"`
}

func TextKind(indicator string) string {
	switch indicator {
	case "critical":
		return "text-error"
	case "major":
		return "text-warning"
	default:
		return "text-info"
	}
}

func BorderKind(indicator string) string {
	switch indicator {
	case "critical":
		return "border-error bg-error/10"
	case "major":
		return "border-warning bg-warning/10"
	default:
		return "border-info bg-info/10"
	}
}

func DotKind(status string) string {
	switch status {
	case "operational":
		return "bg-success shadow-success"
	case "degraded_performance", "partial_outage":
		return "bg-warning shadow-warning"
	case "major_outage":
		return "bg-error shadow-error"
	case "under_maintenance":
		return "bg-info shadow-info"
	default:
		return "bg-muted shadow-muted"
	}
}

func BadgeClass(status string) string {
	switch status {
	case "operational":
		return "border border-success text-success"
	case "degraded_performance", "partial_outage":
		return "bg-warning text-std"
	case "major_outage":
		return "bg-error text-std"
	case "under_maintenance":
		return "border border-info text-info"
	default:
		return "border border-muted text-muted"
	}
}

type CryptoCoin struct {
	ID                                 string    `json:"id"`
	Symbol                             string    `json:"symbol"`
	Name                               string    `json:"name"`
	Image                              string    `json:"image"`
	CurrentPrice                       float64   `json:"current_price"`
	MarketCap                          int64     `json:"market_cap"`
	MarketCapRank                      int       `json:"market_cap_rank"`
	FullyDilutedValuation              int64     `json:"fully_diluted_valuation"`
	TotalVolume                        int64     `json:"total_volume"`
	High24h                            float64   `json:"high_24h"`
	Low24h                             float64   `json:"low_24h"`
	PriceChange24h                     float64   `json:"price_change_24h"`
	PriceChangePercentage24h           float64   `json:"price_change_percentage_24h"`
	MarketCapChange24h                 float64   `json:"market_cap_change_24h"`
	MarketCapChangePercentage24h       float64   `json:"market_cap_change_percentage_24h"`
	CirculatingSupply                  float64   `json:"circulating_supply"`
	TotalSupply                        float64   `json:"total_supply"`
	MaxSupply                          *float64  `json:"max_supply"` // nullable in some APIs
	ATH                                float64   `json:"ath"`
	ATHChangePercentage                float64   `json:"ath_change_percentage"`
	ATHDate                            time.Time `json:"ath_date"`
	ATL                                float64   `json:"atl"`
	ATLChangePercentage                float64   `json:"atl_change_percentage"`
	ATLDate                            time.Time `json:"atl_date"`
	ROI                                *any      `json:"roi"` // null or object depending on API
	LastUpdated                        time.Time `json:"last_updated"`
	PriceChangePercentage24hInCurrency float64   `json:"price_change_percentage_24h_in_currency"`
}

type City struct {
	CityName string  `json:"cityName"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
}

var DefaultCities = []City{
	{
		CityName: "Tokyo",
		Lat:      35.6762,
		Lon:      139.6503,
	},
	{
		CityName: "Rome",
		Lat:      41.9028,
		Lon:      12.4964,
	},
	{
		CityName: "Toronto",
		Lat:      43.6532,
		Lon:      -79.3832,
	},
	{
		CityName: "Seattle",
		Lat:      47.6062,
		Lon:      -122.3321,
	},
	{
		CityName: "Sao Paulo",
		Lat:      -23.5505,
		Lon:      -46.6333,
	},
	{
		CityName: "Dubai",
		Lat:      25.2048,
		Lon:      55.2708,
	},
}

type WeatherResponse struct {
	Latitude             float64      `json:"latitude"`
	Longitude            float64      `json:"longitude"`
	GenerationTimeMs     float64      `json:"generationtime_ms"`
	UTCOffsetSeconds     int          `json:"utc_offset_seconds"`
	Timezone             string       `json:"timezone"`
	TimezoneAbbreviation string       `json:"timezone_abbreviation"`
	Elevation            float64      `json:"elevation"`
	CurrentUnits         CurrentUnits `json:"current_units"`
	Current              Current      `json:"current"`
}

type CurrentUnits struct {
	Time               string `json:"time"`
	Interval           string `json:"interval"`
	Temperature2M      string `json:"temperature_2m"`
	RelativeHumidity2M string `json:"relative_humidity_2m"`
	WindSpeed10M       string `json:"wind_speed_10m"`
	CloudCover         string `json:"cloud_cover"`
}

type Current struct {
	Time               string  `json:"time"`
	Interval           int     `json:"interval"`
	Temperature2M      float64 `json:"temperature_2m"`
	RelativeHumidity2M int     `json:"relative_humidity_2m"`
	WindSpeed10M       float64 `json:"wind_speed_10m"`
	CloudCover         int     `json:"cloud_cover"`
}

type CityWeather struct {
	CityName string          `json:"cityName"`
	Lat      float64         `json:"lat"`
	Lon      float64         `json:"lon"`
	Weather  WeatherResponse `json:"weather"`
}

func NewCityWeather(city City, jsonData []byte) (*CityWeather, error) {
	var weather WeatherResponse

	if err := json.Unmarshal(jsonData, &weather); err != nil {
		return nil, err
	}

	return &CityWeather{
		CityName: city.CityName,
		Lat:      city.Lat,
		Lon:      city.Lon,
		Weather:  weather,
	}, nil
}

type GeoFeature struct {
	Type       string     `json:"type"`
	Properties Properties `json:"properties"`
	Geometry   Geometry   `json:"geometry"`
	ID         string     `json:"id"`
}

func (g GeoFeature) Lat() float64 {
	if len(g.Geometry.Coordinates) > 1 {
		return g.Geometry.Coordinates[1]
	}
	return 0
}

func (g GeoFeature) Lon() float64 {
	if len(g.Geometry.Coordinates) > 0 {
		return g.Geometry.Coordinates[0]
	}
	return 0
}

func (g GeoFeature) Depth() float64 {
	if len(g.Geometry.Coordinates) > 2 {
		return g.Geometry.Coordinates[2]
	}
	return 0
}

type Properties struct {
	Mag     *float64 `json:"mag"`
	Place   string   `json:"place"`
	Time    int64    `json:"time"`
	Updated int64    `json:"updated"`
	TZ      *int     `json:"tz"`
	URL     string   `json:"url"`
	Detail  string   `json:"detail"`
	Felt    *int     `json:"felt"`
	CDI     *float64 `json:"cdi"`
	MMI     *float64 `json:"mmi"`
	Alert   *string  `json:"alert"`
	Status  string   `json:"status"`
	Tsunami int      `json:"tsunami"`
	Sig     int      `json:"sig"`
	Net     string   `json:"net"`
	Code    string   `json:"code"`
	IDs     string   `json:"ids"`
	Sources string   `json:"sources"`
	Types   string   `json:"types"`
	NST     *int     `json:"nst"`
	Dmin    *float64 `json:"dmin"`
	RMS     *float64 `json:"rms"`
	Gap     *float64 `json:"gap"`
	MagType string   `json:"magType"`
	Type    string   `json:"type"`
	Title   string   `json:"title"`
}

type Geometry struct {
	Type        string    `json:"type"`
	Coordinates []float64 `json:"coordinates"` // [lon, lat, depth]
}

func MagToStars(m float64) int {
	switch {
	case m >= 6:
		return 5
	case m >= 5:
		return 4
	case m >= 4:
		return 3
	case m >= 2.5:
		return 2
	default:
		return 1
	}
}

func TimeAgo(timestampMs int64) string {
	now := time.Now().UnixMilli()
	seconds := (now - timestampMs) / 1000

	if seconds < 60 {
		return fmt.Sprintf("%ds ago", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm ago", seconds/60)
	}
	return fmt.Sprintf("%dh ago", seconds/3600)
}
