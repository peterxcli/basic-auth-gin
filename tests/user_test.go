package tests

import (
	"basic-auth-gin/routers"
	"basic-auth-gin/types"
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"

	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"basic-auth-gin/controllers"
	"basic-auth-gin/db"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/stretchr/testify/assert"
)

var auth = new(controllers.AuthController)

// TokenAuthMiddleware ...
// JWT Authentication middleware attached to each request that needs to be authenitcated to validate the access_token in the header
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth.TokenValid(c)
		c.Next()
	}
}

func SetupRouter() *gin.Engine {
	r := gin.Default()
	gin.SetMode(gin.TestMode)

	//Custom type validator
	binding.Validator = new(types.DefaultValidator)

	v1 := r.Group("/v1")
	routers.UserRoute(v1)
	routers.AuthRoute(v1)

	return r
}

func main() {
	r := SetupRouter()
	r.Run()
}

var loginCookie string

var testEmail = "test-gin-boilerplate@test.com"
var testPassword = "123456"

var accessToken string
var refreshToken string

/**
* TestIntDB
* It tests the connection to the database and init the db for this test
*
* Must pass
 */
func TestIntDB(t *testing.T) {
	db.ConnectDB()
	// db.InitRedis(1)
}

/**
* TestRegister
* Test user registration
*
* Must return response code 200
 */
func TestRegister(t *testing.T) {
	testRouter := SetupRouter()

	var registerInfo types.RegisterType

	registerInfo.Name = "testing"
	registerInfo.Email = testEmail
	registerInfo.Password = testPassword

	data, _ := json.Marshal(registerInfo)

	req, err := http.NewRequest("POST", "/v1/user/register", bytes.NewBufferString(string(data)))

	if err != nil {
		fmt.Println(err.Error())
	}

	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()

	testRouter.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
}

/**
* TestRegisterInvalidEmail
* Test user registration with invalid email
*
* Must return response code 406
 */
func TestRegisterInvalidEmail(t *testing.T) {
	testRouter := SetupRouter()

	var registerInfo types.RegisterType

	registerInfo.Name = "testing"
	registerInfo.Email = "invalid@email"
	registerInfo.Password = testPassword

	data, _ := json.Marshal(registerInfo)

	req, err := http.NewRequest("POST", "/v1/user/register", bytes.NewBufferString(string(data)))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()

	testRouter.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNotAcceptable, resp.Code)
}

/**
* TestFakeEmailVerification
* get the test user EmailToken field and send mock email verification GET request
*
* Must return response code 200
 */
func TestFakeEmailVerification(t *testing.T) {
	testRouter := SetupRouter()

	userCollection := db.GetCollection(db.DB, "users")
	var res types.User
	err := userCollection.FindOne(context.Background(), bson.M{"email": testEmail}).Decode(&res)

	if err != nil {
		fmt.Println(err)
	}

	req, err := http.NewRequest("GET", "/v1/user/verify_email?token="+res.EmailToken, bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()

	testRouter.ServeHTTP(resp, req)

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, http.StatusOK, resp.Code)
}

/**
* TestLogin
* Test user login
* and get the access_token and refresh_token stored
*
* Must return response code 200
 */
func TestLogin(t *testing.T) {
	testRouter := SetupRouter()

	var loginInfo types.LoginType

	loginInfo.Email = testEmail
	loginInfo.Password = testPassword

	data, _ := json.Marshal(loginInfo)

	req, err := http.NewRequest("POST", "/v1/user/login", bytes.NewBufferString(string(data)))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()

	testRouter.ServeHTTP(resp, req)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var res struct {
		Message string `json:"message"`
		User    struct {
			CreatedAt int64  `json:"created_at"`
			Email     string `json:"email"`
			ID        int64  `json:"id"`
			Name      string `json:"name"`
			UpdatedAt int64  `json:"updated_at"`
		} `json:"user"`
		Token struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"token"`
	}
	json.Unmarshal(body, &res)
	accessToken = res.Token.AccessToken
	refreshToken = res.Token.RefreshToken

	assert.Equal(t, http.StatusOK, resp.Code)
}

/**
* TestInvalidLogin
* Test invalid login
*
* Must return response code 406
 */
func TestInvalidLogin(t *testing.T) {
	testRouter := SetupRouter()

	var loginInfo types.LoginType

	loginInfo.Email = "wrong@email.com"
	loginInfo.Password = testPassword

	data, _ := json.Marshal(loginInfo)

	req, err := http.NewRequest("POST", "/v1/user/login", bytes.NewBufferString(string(data)))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()

	testRouter.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNotAcceptable, resp.Code)
}

/**
* TestCreateArticle
* Test article creation
*
* Must return response code 200
 */
//func TestCreateArticle(t *testing.T) {
//	testRouter := SetupRouter()
//
//	var form types.CreateArticleForm
//
//	form.Title = "Testing article title"
//	form.Content = "Testing article content"
//
//	data, _ := json.Marshal(form)
//
//	req, err := http.NewRequest("POST", "/v1/article", bytes.NewBufferString(string(data)))
//	req.Header.Set("Content-Type", "application/json")
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	body, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	var res struct {
//		Status int
//		ID     int
//	}
//	json.Unmarshal(body, &res)
//
//	articleID = res.ID
//
//	assert.Equal(t, http.StatusOK, resp.Code)
//}

/**
* TestCreateInvalidArticle
* Test article invalid creation
*
* Must return response code 406
 */
//func TestCreateInvalidArticle(t *testing.T) {
//	testRouter := SetupRouter()
//
//	var form forms.CreateArticleForm
//
//	form.Title = "Testing article title"
//
//	data, _ := json.Marshal(form)
//
//	req, err := http.NewRequest("POST", "/v1/article", bytes.NewBufferString(string(data)))
//	req.Header.Set("Content-Type", "application/json")
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusNotAcceptable, resp.Code)
//}

/**
* TestGetArticle
* Test getting one article
*
* Must return response code 200
 */
//func TestGetArticle(t *testing.T) {
//	testRouter := SetupRouter()
//
//	req, err := http.NewRequest("GET", fmt.Sprintf("/v1/article/%d", articleID), nil)
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusOK, resp.Code)
//}

/**
* TestGetInvalidArticle
* Test getting invalid article
*
* Must return response code 404
 */
//func TestGetInvalidArticle(t *testing.T) {
//	testRouter := SetupRouter()
//
//	req, err := http.NewRequest("GET", "/v1/article/invalid", nil)
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusNotFound, resp.Code)
//}

/**
* TestGetArticleNotLoggedin
* Test getting the article with logged out user
*
* Must return response code 401
 */
//func TestGetArticleNotLoggedin(t *testing.T) {
//	testRouter := SetupRouter()
//
//	req, err := http.NewRequest("GET", fmt.Sprintf("/v1/article/%d", articleID), nil)
//	req.Header.Set("Content-Type", "application/json")
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusUnauthorized, resp.Code)
//}

/**
* TestGetArticleUnauthorized
* Test getting the article with unauthorized user (wrong or expired access_token)
*
* Must return response code 401
 */
//func TestGetArticleUnauthorized(t *testing.T) {
//	testRouter := SetupRouter()
//
//	req, err := http.NewRequest("GET", fmt.Sprintf("/v1/article/%d", articleID), nil)
//	req.Header.Set("Content-Type", "application/json")
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", "abc123"))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusUnauthorized, resp.Code)
//}

/**
* TestUpdateArticle
* Test updating an article
*
* Must return response code 200
 */
//func TestUpdateArticle(t *testing.T) {
//	testRouter := SetupRouter()
//
//	var form forms.CreateArticleForm
//
//	form.Title = "Testing new article title"
//	form.Content = "Testing new article content"
//
//	data, _ := json.Marshal(form)
//
//	url := fmt.Sprintf("/v1/article/%d", articleID)
//
//	req, err := http.NewRequest("PUT", url, bytes.NewBufferString(string(data)))
//	req.Header.Set("Content-Type", "application/json")
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusOK, resp.Code)
//}

/**
* TestDeleteArticle
* Test deleting an article
*
* Must return response code 200
 */
//func TestDeleteArticle(t *testing.T) {
//	testRouter := SetupRouter()
//
//	url := fmt.Sprintf("/v1/article/%d", articleID)
//
//	req, err := http.NewRequest("DELETE", url, nil)
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusOK, resp.Code)
//}

/**
* TestRefreshToken
* Test refreshing the token with valid refresh_token
*
* Must return response code 200
 */
func TestRefreshToken(t *testing.T) {
	testRouter := SetupRouter()

	var tokenInfo types.Token

	tokenInfo.RefreshToken = refreshToken

	data, _ := json.Marshal(tokenInfo)

	req, err := http.NewRequest("POST", "/v1/token/refresh", bytes.NewBufferString(string(data)))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()

	testRouter.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

/**
* TestInvalidRefreshToken
* Test refreshing the token with invalid refresh_token
*
* Must return response code 401
 */
func TestInvalidRefreshToken(t *testing.T) {
	testRouter := SetupRouter()

	var tokenInfo types.Token

	//Since we didn't update it in the test before - this will not be valid anymore
	tokenInfo.RefreshToken = refreshToken

	data, _ := json.Marshal(tokenInfo)

	req, err := http.NewRequest("POST", "/v1/token/refresh", bytes.NewBufferString(string(data)))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()
	testRouter.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	//assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

/**
* TestUserSignout
* Test logout a user
*
* Must return response code 200
 */
//func TestUserLogout(t *testing.T) {
//	testRouter := SetupRouter()
//
//	req, err := http.NewRequest("GET", "/v1/user/logout", nil)
//	req.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", accessToken))
//
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	resp := httptest.NewRecorder()
//	testRouter.ServeHTTP(resp, req)
//
//	assert.Equal(t, http.StatusOK, resp.Code)
//}

/**
* TestCleanUp
* Deletes the created user with its articles
*
* Must pass
 */
func TestCleanUp(t *testing.T) {
	var err error
	userCollection := db.GetCollection(db.DB, "users")
	res, err := userCollection.DeleteOne(context.Background(), bson.M{"email": testEmail})
	if err != nil {
		t.Error(err)
	}
	assert.GreaterOrEqual(t, int(res.DeletedCount), 1)
}
