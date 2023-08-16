package mail

import (
	"fmt"
	"net/smtp"
	"strings"
)

type IMailer interface {
	SendWithActivateToken(email, token string) error
}

func NewMailhogMailer() IMailer {
	return &mailhogMailer{}
}

type mailhogMailer struct {
}

// mailhog
var (
	hostname = "mail"
	port     = 1025
	username = "user@example.com"
	password = "password"
)

func (m *mailhogMailer) SendWithActivateToken(email, token string) error {
	from := "info@login-example.app"
	recipients := []string{email}
	subject := "認証コード by login-example"
	body := fmt.Sprintf("認証用トークンです。\nトークン: %s", token)

	smtpServer := fmt.Sprintf("%s:%d", hostname, port)

	auth := smtp.CRAMMD5Auth(username, password)

	msg := []byte(strings.ReplaceAll(fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", from, strings.Join(recipients, ","), subject, body), "\n", "\r\n"))

	if err := smtp.SendMail(smtpServer, auth, from, recipients, msg); err != nil {
		return err
	}
	return nil
}