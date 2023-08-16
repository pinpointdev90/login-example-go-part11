package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func customHTTPErrorHandler(err error, c echo.Context) {
	c.Logger().Error(err)
	
	// エラーの内容をそのまま返すのは本当はNG
	if err := c.JSON(http.StatusInternalServerError, echo.Map{
		"message": err.Error(),
	}); err != nil {
		c.Logger().Error(err)
	}
}