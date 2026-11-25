package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{"*"}, AllowCredentials: true}))
	v1 := e.Group("/v1")
	v1.GET("/fetch", fetch, jwtAuth)
	v1.GET("/public", public)
	e.Start(":8080")
}

func jwtAuth(next echo.HandlerFunc) echo.HandlerFunc { return next }

// vulnerable: fetches a client URL
func fetch(c echo.Context) error {
	target := c.QueryParam("url")
	resp, err := http.Get(target)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, resp.StatusCode)
}

func public(c echo.Context) error { return c.String(http.StatusOK, "ok") }
