package main

import (
	"login-example/auth"
	"login-example/handler"
	"login-example/mail"
	myMiddleware "login-example/middleware"
	"login-example/repository"
	"login-example/usecase"

	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
)

func NewRouter(db *sqlx.DB, mailer mail.IMailer, jwter *auth.JwtBuilder) *echo.Echo {
	e := echo.New()

	ur := repository.NewUserRepository(db)
	uu := usecase.NewUserUsecase(ur, mailer, jwter)
	uh := handler.NewUserHandler(uu)

	a := e.Group("/api/auth")
	a.POST("/register/initial", uh.PreRegister)
	a.POST("/register/complete", uh.Activate)
	a.POST("/login", uh.Login)

	r := e.Group("/api/restricted")
	r.Use(myMiddleware.AuthMiddleware(jwter))
	r.GET("/user/me", uh.GetMe)

	return e
}