# login-example-go-part11の目標
- ユーザー情報の取得処理を実装する！
- auth_middlewareの実装

前回まででログインはできるようになりました。
今回は本当にログインできているのか？確認するためのエンドポイントを作成します。

# 全体の流れの確認
- 仮登録 /auth/register/initial
    - クライアントからemail, passwordを受け取る
    - email宛に本人確認トークンを送信する
- 本登録 /auth/register/complete
    - クライアントからemailと本人確認トークンを受け取る
    - ユーザーの本登録を行う
- ログイン /auth/login
    - クライアントからemail, passwordを受け取る
    - 認証トークンとしてJWTを返す
- ユーザー情報の取得 /restricted/user/me
    - クライアントからJWTを受け取る
    - ユーザー情報を返す


# 必要な機能を考えよう！

箇条書きしてみます。
- クライアントからJWTを受け取る必要がある
- IDからユーザー情報を取得する

ざっと書き出すとこんな感じです。

ただ、このまま１つのファイルに書き出すとどこに何があるかわからなくなるので役割でまとめてみます。

| パッケージ | 役割 | 機能 |
|:-----------|:------------|:------------|
| Middleware       | 事前・事後処理        | ・リクエストからJWTを受け取り、ユーザー情報をcontextに埋め込む|
| Repository       | DBとのやりとり        | ・UserIDを使ってDBからユーザー情報の取得|
| Usecase     | ログイン処理を行う	 | ・Repositoryからユーザー情報を取得|
| Handler       | リクエストボディの取得レスポンスの作成| ・レスポンスの作成|

こんな感じで実装していきます。
ではやっていきましょう！

# Middleware

## Middleware？
- 「リクエストのJWTを受け取り、ユーザー情報をcontextに埋め込む」はほぼ全ての処理で共通
    - 例えばユーザー情報を更新する処理、削除する処理など。ログイン後に行う処理では必須
- そういった共通の処理はMiddlewareとしてまとめて使いまわせるようにする

というわけで認証用のミドルウェアの実装をやっていきましょう！

middleware/auth_middleware.go
```
package middleware

import (
	"login-example/auth"

	"github.com/labstack/echo/v4"
)

func AuthMiddleware(jwter auth.IJwtParser) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if err := jwter.SetAuthToContext(c); err != nil {
				return err
			}
			
			return next(c)
		}
	}
}
```

## middlewareの解説
```
func MyMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// 本来の処理の前に行いたい処理
		doSomethingBefore()

		defer func(){
			// 本来の処理の後に行いたい処理
			doSomethingAfter()
		}()

		// やりたい処理
		return next(c)
	}
}
```

- next(c)が本来やりたい処理
    - handlerのLogin(c echo.Context) errorやActivate(c echo.Context) errorがここで行われる
- 例えばその前後になんか処理を入れたい、と思ったらこんな感じになる

# Repository

repository/user_repository.go
```
type IUserRepository interface {
	PreRegister(ctx context.Context, u *entity.User) error
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	Delete(ctx context.Context, id entity.UserID) error
	Activate(ctx context.Context, u *entity.User) error
+	Get(ctx context.Context, uid entity.UserID) (*entity.User, error)
}
```

repository/user_repository.go
```
func (r *userRepository) Get(ctx context.Context, uid entity.UserID) (*entity.User, error) {
	query := `SELECT 
		id, email, password, salt, state, activate_token, updated_at, created_at
		FROM user WHERE id = ?`
	u := &entity.User{}
	if err := r.db.GetContext(ctx, u, query, uid); err != nil {
		return nil, fmt.Errorf("failed to get: %w", err)
	}
	return u, nil
}
```

# Usecase
usecase/user_usecase.go
```
type IUserUsecase interface {
	PreRegister(ctx context.Context, email, pw string) (*entity.User, error)
	Activate(ctx context.Context, email, token string) error
	Login(ctx context.Context, email, password string) ([]byte, error)
+	Get(ctx context.Context, uid entity.UserID) (*entity.User, error)
}
```

```
func (uu *userUsecase) Get(ctx context.Context, uid entity.UserID) (*entity.User, error) {
	u, err := uu.ur.Get(ctx, uid)
	if err != nil {
		return nil, err
	}
	return u, nil
}
```

# Handler

handler/user_handler.go
```
type IUserHandler interface {
	PreRegister(c echo.Context) error
	Activate(c echo.Context) error
	Login(c echo.Context) error
+	GetMe(c echo.Context) error
}
```

```
func (h *userHandler) GetMe(c echo.Context) error {
	// echo.ContextからUserIDを取得
	uid, err := auth.GetUserIDFromEchoCtx(c)
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	// UserIDからユーザー情報を取得
	u, err := h.uu.Get(ctx, uid)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"id":         u.ID,
		"email":      u.Email,
		"updated_at": u.UpdatedAt,
		"created_at": u.CreatedAt,
	})
}
```

# Router

router.go
```
package main

import (
	"login-example/auth"
	"login-example/handler"
	"login-example/mail"
+	myMiddleware "login-example/middleware"
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

+	r := e.Group("/api/restricted")
+	r.Use(myMiddleware.AuthMiddleware(jwter))
+	r.GET("/user/me", uh.GetMe)

	return e
}
```


# 確認

これで完成です！
本当にユーザー情報が取得できるか確認していきましょう！
まずはログインしてaccess_tokenを取得します。

```
$ curl -XPOST localhost:8000/api/auth/login \
	-H 'Content-Type: application/json; charset=UTF-8' \
	-d '{"email": "test-user-1@example.xyz", "password": "foobar"}'
```

```
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODg1MzA0NDUsImlhdCI6MTY4ODQ0NDA0NSwiaXNzIjoibG9naW4tZ28iLCJzdWIiOiJhY2Nlc3MtdG9rZW4iLCJ1c2VyX2lkIjoxMDAwMDR9.TAeic3hpLctAdsL2mXvMfwO62Dh3-lfyHxA_NFK8bhAF0vmgN4DXw66KLWLoZDjCzHcVlFsjjQpoZcnfQ-F3RJManB16MsQOMvFHJojruk_cX85eC4JDUg7Zt9ig6VP49Iak3tVbTR1Y__UW8w21-sbXm_3qmFjWLLb2QEj0zsrrvQxf8_M_tJPNlQgemTc9D4DKKG3bcd9NERvM5ABJjNzPQsxV18MxxdGdE3BksWKb6s-NBOoXBKMuG26esvy0YQf-W2t1bIUYh4TmqZJXn1vNCQBSXZ8J9FyqJCoeItQgLFro4-iN_YC06jMDzSSts2QvYR1QE4qYvxNVk7jGdg"}
```

このトークンをAuthorizationヘッダーに含めて/api/restricted/user/meにリクエストを投げましょう。

```
curl -XGET localhost:8000/api/restricted/user/me \
	-H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODg1MzA0NDUsImlhdCI6MTY4ODQ0NDA0NSwiaXNzIjoibG9naW4tZ28iLCJzdWIiOiJhY2Nlc3MtdG9rZW4iLCJ1c2VyX2lkIjoxMDAwMDR9.TAeic3hpLctAdsL2mXvMfwO62Dh3-lfyHxA_NFK8bhAF0vmgN4DXw66KLWLoZDjCzHcVlFsjjQpoZcnfQ-F3RJManB16MsQOMvFHJojruk_cX85eC4JDUg7Zt9ig6VP49Iak3tVbTR1Y__UW8w21-sbXm_3qmFjWLLb2QEj0zsrrvQxf8_M_tJPNlQgemTc9D4DKKG3bcd9NERvM5ABJjNzPQsxV18MxxdGdE3BksWKb6s-NBOoXBKMuG26esvy0YQf-W2t1bIUYh4TmqZJXn1vNCQBSXZ8J9FyqJCoeItQgLFro4-iN_YC06jMDzSSts2QvYR1QE4qYvxNVk7jGdg'
```

```
{"created_at":"2023-07-03T08:56:05.656498Z","email":"test-user-1@example.xyz","id":100004,"updated_at":"2023-07-03T08:56:56.760694Z"}
```

はい、ちゃんとユーザー情報を取得できました！

# まとめ

今回はやった作業はこんな感じ

- ユーザー情報の取得
- middlewareの実装