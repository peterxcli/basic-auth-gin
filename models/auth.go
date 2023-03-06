package models

import (
	"basic-auth-gin/config"
	"basic-auth-gin/types"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	uuid "github.com/google/uuid"
)

// AuthModel ...
type AuthModel struct{}

// CreateToken ...
func (m AuthModel) CreateToken(userID string) (*types.TokenDetails, error) {

	td := &types.TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUUID = uuid.New().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUUID = uuid.New().String()

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userID
	atClaims["exp"] = td.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(config.Env.ACCESS_SECRET))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userID
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(config.Env.REFRESH_SECRET))
	if err != nil {
		return nil, err
	}
	return td, nil
}

// CreateAuth ...
// func (m AuthModel) CreateAuth(userid string, td *types.TokenDetails) error {
// 	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
// 	rt := time.Unix(td.RtExpires, 0)
// 	now := time.Now()

// 	errAccess := db.GetRedis().Set(td.AccessUUID, userid, at.Sub(now)).Err()
// 	if errAccess != nil {
// 		return errAccess
// 	}
// 	errRefresh := db.GetRedis().Set(td.RefreshUUID, userid, rt.Sub(now)).Err()
// 	if errRefresh != nil {
// 		return errRefresh
// 	}
// 	return nil
// }

// ExtractToken ...
func (m AuthModel) ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// VerifyToken ...
func (m AuthModel) VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := m.ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Env.ACCESS_SECRET), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// TokenValid ...
func (m AuthModel) TokenValid(r *http.Request) error {
	token, err := m.VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

// ExtractTokenMetadata ...
func (m AuthModel) ExtractTokenMetadata(r *http.Request) (*types.AccessDetails, error) {
	token, err := m.VerifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUUID, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userID := fmt.Sprintf("%.f", claims["user_id"])
		if err != nil {
			return nil, err
		}
		return &types.AccessDetails{
			AccessUUID: accessUUID,
			UserID:     userID,
		}, nil
	}
	return nil, err
}

// // FetchAuth ...
// func (m AuthModel) FetchAuth(authD *types.AccessDetails) (int64, error) {
// 	userid, err := db.GetRedis().Get(authD.AccessUUID).Result()
// 	if err != nil {
// 		return 0, err
// 	}
// 	userID, _ := strconv.ParseInt(userid, 10, 64)
// 	return userID, nil
// }

// // DeleteAuth ...
// func (m AuthModel) DeleteAuth(givenUUID string) (int64, error) {
// 	deleted, err := db.GetRedis().Del(givenUUID).Result()
// 	if err != nil {
// 		return 0, err
// 	}
// 	return deleted, nil
// }
