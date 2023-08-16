package usecase

import (
	"context"
	"database/sql"
	"errors"
	"login-example/entity"
	"login-example/mail"
	"login-example/repository"
	"math/rand"
)

type IUserUsecase interface {
	PreRegister(ctx context.Context, email, pw string) (*entity.User, error)
	Activate(ctx context.Context, email, token string) error
	Login(ctx context.Context, email, password string) ([]byte, error)
	Get(ctx context.Context, uid entity.UserID) (*entity.User, error)

}

type userUsecase struct {
	ur     repository.IUserRepository
	mailer mail.IMailer
}

func NewUserUsecase(ur repository.IUserRepository, mailer mail.IMailer, jwter auth.IJwtGenerator) IUserUsecase {
	return &userUsecase{ur: ur, mailer: mailer, jwter: jwter}
 }

func (uu *userUsecase) PreRegister(ctx context.Context, email, pw string) (*entity.User, error) {
	u, err := uu.ur.GetByEmail(ctx, email)

	// ユーザーが存在しない場合、sql.ErrNoRowsを受け取るはずなので、存在しない場合はそのまま仮登録処理を行う
	if errors.Is(err, sql.ErrNoRows) {
		return uu.preRegister(ctx, email, pw)
		// それ以外のエラーの場合は想定外なのでそのまま返す
	} else if err != nil {
		return nil, err
	}

	// ユーザーがすでにアクティブの場合はエラーを返す
	if u.IsActive() {
		return nil, errors.New("user already active")
	}

	// ユーザーがアクティブではない場合、ユーザーを削除して、再度仮登録処理を行う
	if err := uu.ur.Delete(ctx, u.ID); err != nil {
		return nil, err
	}
	return uu.preRegister(ctx, email, pw)
}

// 仮登録処理を行う
func (uu *userUsecase) preRegister(ctx context.Context, email, pw string) (*entity.User, error) {
	salt := createRandomString(30)
	activeToken := createRandomString(8)

	u := &entity.User{}

	// パスワードのハッシュ化をする
	hashed, err := u.CreateHashedPassword(pw, salt)
	if err != nil {
		return nil, err
	}

	u.Email = email
	u.Salt = salt
	u.Password = hashed
	u.ActivateToken = activeToken
	u.State = entity.UserInactive

	// DBへの仮登録処理を行う
	if err := uu.ur.PreRegister(ctx, u); err != nil {
		return nil, err
	}
	// email宛に、本人確認用のトークンを送信する
	if err := uu.mailer.SendWithActivateToken(email, u.ActivateToken); err != nil {
		return nil, err
	}
	return u, err
}

// lengthの長さのランダムな文字列(a-zA-Z0-9)を作成する
func createRandomString(length uint) string {
	var letterBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// ユーザーのstateをactivateに更新する
func (uu *userUsecase) Activate(ctx context.Context, email, token string) error {
	// emailをもとにDBからユーザーを取得する。
	u, err := uu.ur.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	// すでにユーザーがアクティブの場合、エラーを返す
	if u.IsActive() {
		return errors.New("user already active")
	}

	// トークンが一致しなければエラーをかえす
	if token != u.ActivateToken {
		return errors.New("invalid token")
	}

	// トークンが作成されて30分以上ならエラーをかえす
	if u.UpdatedAt.Add(30*time.Minute).Compare(time.Now()) != +1 {
		return errors.New("token expired")
	}

	if err := uu.ur.Activate(ctx, u); err != nil {
		return err
	}
	return nil
}

func (uu *userUsecase) Login(ctx context.Context, email, password string) ([]byte, error) {
	// emailからユーザー情報を取得する
	u, err := uu.ur.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	// ユーザーがアクティブでないならエラー
	if !u.IsActive() {
		return nil, errors.New("user inactive")
	}
	// ユーザーのパスワードを検証
	if err := u.Authenticate(password); err != nil {
		return nil, err
	}
	// ユーザー情報からJWTを作成
	tok, err := uu.jwter.GenerateJWT(u)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (uu *userUsecase) Get(ctx context.Context, uid entity.UserID) (*entity.User, error) {
	u, err := uu.ur.Get(ctx, uid)
	if err != nil {
		return nil, err
	}
	return u, nil
}