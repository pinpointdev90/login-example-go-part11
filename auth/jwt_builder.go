package auth

import (
	_ "embed"
	"errors"
	"fmt"
	"login-go/entity"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	//go:embed keys/secret.pem
	secretKey []byte
	//go:embed keys/public.pem
	publicKey []byte
	
	// アクセストークンの有効期限
	expAccess = 30 * time.Minute
)

const (
	userIDClaim      = "user_id"
	issClaim         = "login-go"
	accessSubClaim   = "access-token"
	userIDContextKey = "user_id"
)

type IJwtGenerator interface {
	GenerateToken(u *entity.User) ([]byte, error)
}

type IJwtParser interface {
	SetAuthToContext(c echo.Context) error
}

type JwtBuilder struct {
	secretKey jwk.Key
	publicKey jwk.Key
}

func NewJwtBuilder() (*JwtBuilder, error) {
	secKey, err := jwk.ParseKey(secretKey, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	pubKey, err := jwk.ParseKey(publicKey, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	j := &JwtBuilder{}
	j.secretKey = secKey
	j.publicKey = pubKey
	return j, nil
}

// JWTを作成する
func (j *JwtBuilder) GenerateToken(u *entity.User) ([]byte, error) {
	// JWTを作成
	tok, err := jwt.NewBuilder().
		Issuer(issClaim).
		Subject(accessSubClaim).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(expAccess)).
		Claim(userIDClaim, u.ID).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to jwt build: %w", err)
	}

	// JWTを秘密鍵で署名化
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, j.secretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return signed, nil
}

// contextに認証情報をセットする
func (j *JwtBuilder) SetAuthToContext(c echo.Context) error {
	// リクエストからJWTを取得＆検証
	tok, err := j.parseRequest(c.Request())
	if err != nil {
		return err
	}

	// JWTからuser_idを取得する
	// idの型はtokenから取得した段階ではfloat64
	id, ok := tok.Get(userIDClaim)
	if !ok {
		return errors.New("failed to get user_id from token")
	}
	uid, ok := id.(float64)
	if !ok {
		return fmt.Errorf("get invalid user_id: %v, %T", id, id)
	}

	// ContextにUserIDをセットする
	c.Set(userIDContextKey, entity.UserID(uid))

	return nil
}

func GetUserIDFromEchoCtx(c echo.Context) (entity.UserID, error) {
	got := c.Get(userIDContextKey)
	uid, ok := got.(entity.UserID)
	if !ok {
		return 0, fmt.Errorf("get invalid user_id: %v, %T", got, got)
	}

	return uid, nil
}

// リクエストからJWTの取得し、検証を行う
func (j *JwtBuilder) parseRequest(r *http.Request) (jwt.Token, error) {
	// AuthorizationヘッダーからJWTを取得
	// 公開鍵を用いてjwtを検証、issとsubも検証する
	tok, err := jwt.ParseRequest(r,
		jwt.WithKey(jwa.RS256, j.publicKey),
		jwt.WithIssuer(issClaim),
		jwt.WithSubject(accessSubClaim),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}
	return tok, nil
}
