package main

import (
	"fmt"
	"login-example/db"
	"login-example/mail"

	"github.com/go-playground/validator/v10"
)

func main() {
	db, err := db.NewDB()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	mailer := mail.NewMailhogMailer()

	jwter, err := auth.NewJwtBuilder()
	if err != nil {
		fmt.Println(err)
		return
	}

	e := NewRouter(db, mailer, jwter)

	// error_handler.goの内容を登録してます。
	e.HTTPErrorHandler = customHTTPErrorHandler
	
	// validator.goの内容を登録してます。
	e.Validator = &CustomValidator{validator: validator.New()}

	e.Logger.Fatal(e.Start(":8000"))
}