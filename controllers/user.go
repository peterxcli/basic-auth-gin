package controllers

import (
	"basic-auth-gin/db"
	"basic-auth-gin/models"
	"basic-auth-gin/types"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"net/http"

	"basic-auth-gin/config"
	"encoding/json"

	"github.com/gin-gonic/gin"
)

// UserController ...
type UserController struct{}

var userModel = new(models.UserModel)
var userType = new(types.UserType)

// getUserID ...
func getUserID(c *gin.Context) (userID int64) {
	//MustGet returns the value for the given key if it exists, otherwise it panics.
	return c.MustGet("userID").(int64)
}

// Login logs in a user
// @Summary Logs in a user
// @Description Logs in a user and returns user details and authentication token.
// @Accept json
// @Produce json
// @Tags user
// @Param loginType body types.LoginType true "Login credentials"
// @Success 200 {object} types.LoginResponseType "return with token and user detail"
// @Failure 401 {object} types.ErrorResponse "please confirm your email first"
// @Failure 406 {object} types.ErrorResponse
// @Router /user/login [post]
func (ctrl UserController) Login(c *gin.Context) {
	var loginType types.LoginType

	if validationErr := c.ShouldBindJSON(&loginType); validationErr != nil {
		message := userType.Login(validationErr)
		c.AbortWithStatusJSON(http.StatusNotAcceptable, types.ErrorResponse{Message: message})
		return
	}

	user, err := userModel.Login(loginType)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, types.ErrorResponse{Message: "Invalid login details"})
		return
	}

	if user.EmailConfirmed == false {
		c.AbortWithStatusJSON(http.StatusUnauthorized, types.ErrorResponse{Message: "please confirm your email first"})
		return
	}

	var token types.Token
	tokenDetails, err := authModel.CreateToken(user.Id.Hex())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, types.ErrorResponse{Message: "create token failed"})
		return
	}

	token.AccessToken = tokenDetails.AccessToken
	token.RefreshToken = tokenDetails.RefreshToken

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged in", "user": user, "token": token})
}

// Register godoc
// @Summary Register a new user
// @Description Registers a new user with the provided email, password, and name
// @Tags user
// @Accept  json
// @Produce  json
// @Param registerInfo body types.RegisterType true "User registration information"
// @Success 200 {object} types.RegisterResponseType
// @Failure 406 {object} types.ErrorResponse
// @Failure 406 {object} types.ErrorResponse
// @Router /users/register [post]
func (ctrl UserController) Register(c *gin.Context) {
	var registerUser types.RegisterType

	if validationErr := c.ShouldBindJSON(&registerUser); validationErr != nil {
		message := userType.Register(validationErr)
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": message})
		return
	}
	user, err := userModel.Register(registerUser)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
		return
	}
	tokenDetails, err := authModel.CreateToken(user.Id.String())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
		return
	}
	_, err = userModel.Update(bson.M{"_id": user.Id}, bson.M{"$set": bson.M{"emailToken": tokenDetails.AccessToken}})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
		return
	}
	err = ctrl.sendEmail(registerUser.Email, tokenDetails.AccessToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Successfully registered", "user": user})
}

type SendGridEmail struct {
	Personalizations []Personalization `json:"personalizations"`
	From             Email             `json:"from"`
	Content          []Content         `json:"content"`
}

type Personalization struct {
	To      []Email `json:"to"`
	Subject string  `json:"subject"`
}

type Email struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
}

type Content struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (ctrl UserController) sendEmail(recipientEmail string, token string) error {
	// Set up the email data
	email := &SendGridEmail{
		Personalizations: []Personalization{
			{
				To: []Email{
					{
						Email: recipientEmail,
					},
				},
				Subject: "Email verification",
			},
		},
		From: Email{
			Email: config.Env.EMAIL,
		},
		Content: []Content{
			{
				Type:  "text/plain",
				Value: "Please click this link to verify your email: " + config.Env.EMAIL_CONFIRM_URI + token,
			},
		},
	}

	// Serialize the email data to JSON
	payload, err := json.Marshal(email)
	if err != nil {
		return err
	}

	// Set up the HTTP request
	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	fmt.Println("api_key", config.Env.SENDGRID_API_KEY)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.Env.SENDGRID_API_KEY))
	req.Header.Set("Content-Type", "application/json")

	// Send the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	// Check the HTTP response status code
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		fmt.Println("\033[37;101m" + bodyString + "\033[0m")
		return errors.New("error sending email")
	}

	return nil
}

// VerifyEmailHandler handles the email verification process for a user by verifying the token provided in the query string.
// If the token is valid and associated with a user in the database, the user's emailConfirmed field is updated to true.
// If successful, a JSON response with a success message is returned.
// If the token is invalid or not associated with a user, the request is aborted with an appropriate status code.
// @Summary Verify user email
// @Description Verify user email by token
// @Tags user
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} types.SuccessResponse "Email verification successful"
// @Failure 401 {object} string "Unauthorized"
// @Failure 500 {object} string "Internal Server Error"
// @Router /api/users/verify_email [get]
func (ctrl UserController) VerifyEmailHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Query("token")
		// Verify token here using the jwt package or other means
		_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			//Make sure that the token method conform to "SigningMethodHMAC"
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.Env.ACCESS_SECRET), nil
		})
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Find the user by the email associated with the token
		var user models.UserSchema
		err = db.GetCollection(db.DB, "users").FindOne(context.Background(), bson.M{"emailToken": token}).Decode(&user)
		if err != nil {
			fmt.Println(err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Update the user's emailConfirmed field to true
		_, err = userModel.Update(bson.M{"_id": user.Id}, bson.M{"$set": bson.M{"emailConfirmed": true}})
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Redirect the user to a success page or show a success message
		c.JSON(http.StatusOK, gin.H{
			"message": "Email verification successful",
		})
	}
}

// OpenAuthGoogle initiates Google OAuth2 authentication flow
// @Summary Initiate Google OAuth2 authentication flow
// @Description Redirects user to Google OAuth2 authorization page for authentication.
// @Produce html
// @Tags user
// @Success 302 {string} html "Redirects user to Google OAuth2 authorization page."
// @Router /user/auth/google [get]
func (ctrl UserController) OpenAuthGoogle(c *gin.Context) {
	query := url.Values{
		"redirect_uri":  {config.Env.REDIRECT_URI},
		"client_id":     {config.Env.GOOGLE_CLIENT_ID},
		"access_type":   {"offline"},
		"response_type": {"code"},
		"prompt":        {"consent"},
		"scope": {
			strings.Join([]string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			}, " "),
		},
	}
	authURL := "https://accounts.google.com/o/oauth2/v2/auth"
	c.Redirect(http.StatusFound, authURL+"?"+query.Encode())
}

// OpenAuthGoogleCallBack
// @Router /user/auth/google/callback [get]
// @Summary Handle Google OAuth callback
// @Description Exchanges the authorization code received from Google OAuth with access and ID tokens, and retrieves user information from Google's API.
// @Produce json
// @tags user
// @Param code query string true "Authorization code received from Google OAuth"
// @Success 302 {string} string "Redirects to the client app with a JWT token in the URL hash"
// @Failure 403 {string} string "Forbidden"
// @Failure 500 {string} string "Internal Server Error"
func (ctrl UserController) OpenAuthGoogleCallBack(c *gin.Context) {
	code := c.Query("code")

	// set request parameters
	body := url.Values{}
	body.Add("code", code)
	body.Add("client_id", config.Env.GOOGLE_CLIENT_ID)
	body.Add("client_secret", config.Env.GOOGLE_CLIENT_SECRET)
	body.Add("redirect_uri", config.Env.REDIRECT_URI)
	body.Add("grant_type", "authorization_code")

	// make a POST request to the Google token endpoint
	url := "https://oauth2.googleapis.com/token"
	response, err := http.PostForm(url, body)
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	defer response.Body.Close()

	// check if the response is valid
	if response.StatusCode != http.StatusOK {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// extract the tokens from the response
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// make a GET request to get user information
	url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=" + tokens.AccessToken
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tokens.IDToken)

	client := http.Client{}
	response, err = client.Do(req)
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	defer response.Body.Close()

	// check if the response is valid
	if response.StatusCode != http.StatusOK {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// extract user data from the response
	var data struct {
		Email string `json:"email"`
		ID    string `json:"id"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	fmt.Print(data)
	// set the user data in the request body
	c.Set("email", data.Email)
	c.Set("externalId", data.ID)
	c.Set("name", data.Name)
	c.Set("externalType", "Google")

	c.Next()
}

// InsertOrUpdateWithOpenAuth
// @Router /user/auth/google/callback [get]
// @Summary Inserts or updates a user with the data received from Google OAuth
// @Description Inserts or updates a user in the database with the user data received from Google OAuth, and returns a JWT token to the client app.
// @Tags user
// @Produce json
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
func (ctrl UserController) InsertOrUpdateWithOpenAuth(c *gin.Context) {
	// extract user data from the request body
	email := c.GetString("email")
	externalId := c.GetString("externalId")
	externalType := c.GetString("externalType")
	name := c.GetString("name")
	permissionLevel := c.GetInt("permissionLevel")

	// check if the user already exists
	hadUser, err := userModel.EmailExist(email)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	var res = &models.UserSchema{}
	if hadUser == true {
		var user = &types.UserInfoWithOAuth{
			ExternalId:   externalId,
			ExternalType: externalType,
		}

		res, err = userModel.InsertOrUpdateByEmail(email, user)
	} else { // no account found
		// create a new user
		password, err := uuid.NewUUID()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		var user = &models.UserSchema{
			Id:              primitive.NewObjectID(),
			Email:           email,
			ExternalId:      externalId,
			ExternalType:    externalType,
			Name:            name,
			PermissionLevel: permissionLevel,
			Password:        password.String(),
		}
		res, err = userModel.InsertOrUpdateByEmail(user.Email, user)
	}
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if hadUser == false {
		tokenDetails, err := authModel.CreateToken(res.Id.String())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
			return
		}
		_, err = userModel.Update(bson.M{"_id": res.Id}, bson.M{"$set": bson.M{"emailToken": tokenDetails.AccessToken}})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
			return
		}
		ctrl.sendEmail(res.Email, tokenDetails.AccessToken)
	}
	// set the user ID in the request body
	c.Set("userId", res.Id.Hex())

	c.Next()
}

// RedirectWithToken @Router /user/auth/google/callback [get]
// @Summary Redirects to the client app with a JWT token in the URL hash
// @Description Redirects to the client app with a JWT token in the URL hash, which can be used to authenticate future requests.
// @Produce json
// @Param token query string true "JWT token to be included in the URL hash"
// @Success 302 {string} string "Redirects to the client app with a JWT token in the URL hash"
// @Failure 400 {string} string "Bad Request"
func (ctrl UserController) RedirectWithToken(c *gin.Context) {
	userId := c.GetString("userId")
	tokenDetails, err := authModel.CreateToken(userId)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, types.ErrorResponse{Message: "create token failed"})
		return
	}
	var token types.Token
	token.AccessToken = tokenDetails.AccessToken
	token.RefreshToken = tokenDetails.RefreshToken
	query := url.Values{
		"accesstoken":  {tokenDetails.AccessToken},
		"refreshtoken": {tokenDetails.RefreshToken},
	}
	loginwithTokenInfoURL := fmt.Sprintf("%s/auth?%s", config.Env.FRONTEND_URI, query.Encode())
	c.Redirect(http.StatusFound, loginwithTokenInfoURL)
}

// UserAuth retrieves user information by extracting the userID from the JWT token and returns a JSON response
// containing the user information if the user is authenticated and their email is confirmed.
// @Summary Retrieves user information after validating JWT token
// @Description Retrieves user information after validating JWT token
// @Accept json
// @Produce json
// @Tags user
// @Success 200 {object} types.UserTokenAuthResponseType
// @Failure 401 {string} string "please confirm your email first"
// @Failure 406 {string} string "Not Acceptable"
// @Router /user/auth [get]
func (ctrl UserController) UserAuth(c *gin.Context) {
	//MustGet returns the value for the given key if it exists, otherwise it panics.
	userID := c.GetString("userID")
	fmt.Println(userID)
	user, err := userModel.One(userID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, types.ErrorResponse{Message: err.Error()})
		return
	}

	if user.EmailConfirmed == false {
		c.AbortWithStatusJSON(http.StatusUnauthorized, types.ErrorResponse{Message: "please confirm your email first"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "authentication passed", "user": user})
}

// Logout ...
// func (ctrl UserController) Logout(c *gin.Context) {

// 	au, err := authModel.ExtractTokenMetadata(c.Request)
// 	if err != nil {
// 		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "User not logged in"})
// 		return
// 	}

// 	deleted, delErr := authModel.DeleteAuth(au.AccessUUID)
// 	if delErr != nil || deleted == 0 { //if any goes wrong
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid request"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
// }
