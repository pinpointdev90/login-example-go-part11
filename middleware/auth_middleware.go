package middleware

import (
	"login-example/auth"

	"github.com/labstack/echo/v4"
)

func AuthMiddleware(jwter auth.IJwtParser) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// 本来の処理の前に行いたい処理
			if err := jwter.SetAuthToContext(c); err != nil {
				return err
			}
			
			// やりたい処理
			return next(c)
		}
	}
}