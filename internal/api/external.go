package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

func fetchJSON(url string, target any) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Error("fetchJSON", slog.String("error", err.Error()))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func GetGithubStatus() (*models.GithubStatusResponse, error) {
	url := "https://www.githubstatus.com/api/v2/summary.json"

	var res models.GithubStatusResponse
	if err := fetchJSON(url, &res); err != nil {
		return nil, err
	}

	res.Components = helpers.FilteredSlice(res.Components, func(gc models.GithubComponent) bool { return gc.Showcase })

	return &res, nil
}

func GetCryptoCoins() ([]models.CryptoCoin, error) {
	url := "https://api.coingecko.com/api/v3/coins/markets" +
		"?vs_currency=usd" +
		"&ids=bitcoin,ethereum,solana,filecoin,polkadot" +
		"&order=market_cap_desc" +
		"&price_change_percentage=24h"

	var coins []models.CryptoCoin
	if err := fetchJSON(url, &coins); err != nil {
		return nil, err
	}

	return coins, nil
}

func GetCityWeather(city models.City) (*models.CityWeather, error) {
	url := fmt.Sprintf(
		"https://api.open-meteo.com/v1/forecast?latitude=%f&longitude=%f&current=temperature_2m,relative_humidity_2m,wind_speed_10m,cloud_cover",
		city.Lat,
		city.Lon,
	)

	var weather models.WeatherResponse
	if err := fetchJSON(url, &weather); err != nil {
		return nil, err
	}

	return &models.CityWeather{
		CityName: city.CityName,
		Lat:      city.Lat,
		Lon:      city.Lon,
		Weather:  weather,
	}, nil
}

type GeoFeatureCollection struct {
	Type     string              `json:"type"`
	Features []models.GeoFeature `json:"features"`
}

func GetEarthquakes() ([]models.GeoFeature, error) {
	url := "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson"

	var res GeoFeatureCollection
	if err := fetchJSON(url, &res); err != nil {
		return nil, err
	}

	return res.Features, nil
}
