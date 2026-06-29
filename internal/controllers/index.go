package controllers

import (
	"log/slog"
	"net/http"

	"github.com/Francesco99975/authpoc/internal/api"
	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/httperr"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

func Index() echo.HandlerFunc {
	return func(c echo.Context) error {
		herr := httperr.New("index", "Index", c.Request().Header.Get("X-Request-ID"))
		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := auth.GetActiveSession(c.Request(), repo)
		slog.Debug("user", "user", user, "err", err)
		if err != nil && user != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}

		if user != nil {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}

		return c.Redirect(http.StatusSeeOther, "/auth")

	}
}

func Auth() echo.HandlerFunc {
	return func(c echo.Context) error {
		herr := httperr.New("auth", "Auth", c.Request().Header.Get("X-Request-ID"))
		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil && user != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}
		if user != nil {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}

		data := models.GetDefaultSite("Authenthication", c.Request())
		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		slog.Debug("Canonical", slog.String("canonical", data.Metatags.Canonical))

		html := helpers.MustRenderHTML(views.Index(data))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func Dashboard() echo.HandlerFunc {
	return func(c echo.Context) error {
		herr := httperr.New("dashboard", "Dashboard", c.Request().Header.Get("X-Request-ID"))
		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil && user != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}
		if user == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		data := models.GetDefaultSite("Dashboard", c.Request())

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		userID, err := uuid.Parse(user.ID)
		if err != nil {
			return herr.HandleEchoPage(http.StatusInternalServerError, err)
		}

		slog.Debug("Authenticated user ID", slog.String("userID", userID.String()))

		html := helpers.MustRenderHTML(views.Dashboard(data, views.DashboardProps{
			Username: user.Username,
			Email:    user.Email,
		}))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func RefreshGithubData() echo.HandlerFunc {
	return func(c echo.Context) error {
		githubStatus, err := api.GetGithubStatus()
		if err != nil {
			slog.Warn("Failed to get github status", slog.String("error", err.Error()))
		}

		html := helpers.MustRenderHTML(views.GithubStatus(githubStatus))

		return c.Blob(http.StatusOK, "text/html", html)
	}

}

func RefreshCryptoData() echo.HandlerFunc {
	return func(c echo.Context) error {
		cryptoCoins, err := api.GetCryptoCoins()
		if err != nil {
			slog.Warn("Failed to get crypto coins", slog.String("error", err.Error()))
		}

		html := helpers.MustRenderHTML(views.CryptoCoinsDisplay(cryptoCoins))

		return c.Blob(http.StatusOK, "text/html", html)
	}

}

func RefreshWeatherData() echo.HandlerFunc {
	return func(c echo.Context) error {
		citiesWeather := make([]models.CityWeather, 0)
		for _, city := range models.DefaultCities {
			weather, err := api.GetCityWeather(city)
			if err != nil {
				slog.Warn("Failed to get city weather", slog.String("error", err.Error()))
			}
			citiesWeather = append(citiesWeather, *weather)
		}

		html := helpers.MustRenderHTML(views.CitiesWeatherDisplay(citiesWeather))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func RefreshQuakeData() echo.HandlerFunc {
	return func(c echo.Context) error {
		quakes, err := api.GetEarthquakes()
		if err != nil {
			slog.Warn("Failed to get earthquakes", slog.String("error", err.Error()))
		}

		html := helpers.MustRenderHTML(views.QuakesDisplay(quakes))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}
