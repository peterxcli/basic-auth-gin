package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"basic-auth-gin/config"
	"basic-auth-gin/types"

	docs "basic-auth-gin/docs"
	"basic-auth-gin/routers"

	"github.com/gin-contrib/gzip"
	uuid "github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// CORSMiddleware ...
// CORS (Cross-Origin Resource Sharing)
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Origin, Authorization, Accept, Client-Security-Token, Accept-Encoding, x-access-token")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			fmt.Println("OPTIONS")
			c.AbortWithStatus(200)
		} else {
			c.Next()
		}
	}
}

// RequestIDMiddleware ...
// Generate a unique ID and attach it to each request for future reference or use
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		uuid := uuid.New()
		c.Writer.Header().Set("X-Request-Id", uuid.String())
		c.Next()
	}
}

func main() {
	env := config.Env.ENV
	port := config.Env.PORT
	ssl := config.Env.SSL
	api_version := config.Env.API_VERSION

	if env == "PRODUCTION" {
		gin.SetMode(gin.ReleaseMode)
	}

	//Start the default gin server
	r := gin.Default()

	//Custom type validator
	binding.Validator = new(types.DefaultValidator)

	r.Use(CORSMiddleware())
	r.Use(RequestIDMiddleware())
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	v1 := r.Group("/v1")
	routers.UserRoute(v1)
	routers.AuthRoute(v1)
	// {
	// 	/*** START USER ***/
	// 	// v1.GET("/user/logout", user.Logout)

	// 	/*** START Article ***/
	// 	// article := new(controllers.ArticleController)

	// 	// v1.POST("/article", TokenAuthMiddleware(), article.Create)
	// 	// v1.GET("/articles", TokenAuthMiddleware(), article.All)
	// 	// v1.GET("/article/:id", TokenAuthMiddleware(), article.One)
	// 	// v1.PUT("/article/:id", TokenAuthMiddleware(), article.Update)
	// 	// v1.DELETE("/article/:id", TokenAuthMiddleware(), article.Delete)
	// }

	r.LoadHTMLGlob("./public/html/*")

	r.Static("/public", "./public")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"packageVersion": "v0.01",
			"goVersion":      runtime.Version(),
		})
	})
	docs.SwaggerInfo.BasePath = "/v1"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}
	if env == "LOCAL" {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	}

	r.NoRoute(func(c *gin.Context) {
		c.HTML(404, "404.html", gin.H{})
	})

	log.Printf("\n\n PORT: %s \n ENV: %s \n SSL: %s \n Version: %s \n\n", port, env, ssl, api_version)

	if ssl == "TRUE" {

		//Generated using sh generate-certificate.sh
		SSLKeys := &struct {
			CERT string
			KEY  string
		}{
			CERT: "./cert/myCA.cer",
			KEY:  "./cert/myCA.key",
		}

		r.RunTLS(":"+port, SSLKeys.CERT, SSLKeys.KEY)
	} else {
		r.Run(":" + port)
	}
}
