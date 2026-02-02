package controllers

import (
	"net/http"

	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/views"
	"github.com/labstack/echo/v4"
)

func About() echo.HandlerFunc {
	return func(c echo.Context) error {

		data := models.GetDefaultSite("Dashboard")

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		html := helpers.MustRenderHTML(views.About(data))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}
