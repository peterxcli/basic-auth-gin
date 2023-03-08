package controllers

import (
	"fmt"
	"net/http"

	"basic-auth-gin/config"
	"basic-auth-gin/models"
	"basic-auth-gin/types"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
)

// AuthController ...
type AuthController struct{}

var authModel = new(models.AuthModel)

// TokenValid ...
func (ctl AuthController) TokenValid(c *gin.Context) {

	tokenAuth, err := authModel.ExtractTokenMetadata(c.Request)
	if err != nil {
		//Token either expired or not valid
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Please login first"})
		return
	}

	// userID, err := authModel.FetchAuth(tokenAuth)
	// if err != nil {
	// 	//Token does not exists in Redis (User logged out or expired)
	// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Please login first"})
	// 	return
	// }
	//To be called from GetUserID()
	c.Set("userID", tokenAuth.UserID)
}

// Refresh token
// @Summary Refresh the access token using a refresh token
// @Description Refreshes the access token using a refresh token if it is still valid
// @Tags auth
// @Accept  json
// @Produce  json
// @Param token body types.Token true "Refresh token"
// @Success 200 {object} types.Token
// @Failure 406 {object} types.ErrorResponseInvalidToken
// @Failure 401 {object} types.ErrorResponse
// @Failure 401 {object} types.ErrorResponse
// @Failure 401 {object} types.ErrorResponse
// @Failure 403 {object} types.ErrorResponse
// @Router /token/refresh [post]
func (ctl AuthController) Refresh(c *gin.Context) {
	var _token types.Token

	if c.ShouldBindJSON(&_token) != nil {
		c.JSON(http.StatusNotAcceptable, gin.H{"message": "Invalid type", "token": _token})
		c.Abort()
		return
	}

	//verify the token
	token, err := jwt.Parse(_token.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Env.REFRESH_SECRET), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "token verify failed"})
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization, please login again(token vaild not ok)"})
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		_, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization, please login again (refresh_uuid error)"})
			return
		}
		userID := claims["user_id"].(string)

		//Create new pairs of refresh and access tokens
		ts, createErr := authModel.CreateToken(userID)
		if createErr != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "Invalid authorization, please login again"})
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusOK, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization, please login again"})
	}
}
