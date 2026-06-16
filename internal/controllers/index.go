package controllers

import (
	"fmt"
	"net/http"

	"github.com/Francesco99975/authpoc/internal/api"
	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func Index() echo.HandlerFunc {
	return func(c echo.Context) error {

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if user != nil {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}

		return c.Redirect(http.StatusSeeOther, "/auth")

	}
}

func Auth() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if user != nil {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}

		data := models.GetDefaultSite("Authenthication", c.Request())
		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		log.Debugf("Canonical: %s", data.Metatags.Canonical)

		html := helpers.MustRenderHTML(views.Index(data))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func Dashboard() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if user == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		data := models.GetDefaultSite("Dashboard", c.Request())

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		userID, err := uuid.Parse(user.ID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		log.Debugf("Authenticated user ID: %s", userID.String())

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
			log.Warnf("Failed to get github status: %v", err)
		}

		html := helpers.MustRenderHTML(views.GithubStatus(githubStatus))

		return c.Blob(http.StatusOK, "text/html", html)
	}

}

func RefreshCryptoData() echo.HandlerFunc {
	return func(c echo.Context) error {
		cryptoCoins, err := api.GetCryptoCoins()
		if err != nil {
			log.Warnf("Failed to get crypto coins: %v", err)
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
				log.Warnf("Failed to get city weather: %v", err)
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
			log.Warnf("Failed to get earthquakes: %v", err)
		}

		html := helpers.MustRenderHTML(views.QuakesDisplay(quakes))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}
