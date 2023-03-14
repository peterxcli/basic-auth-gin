package routers

import (
	"basic-auth-gin/controllers"
	"basic-auth-gin/middlewares"

	"github.com/gin-gonic/gin"
)

// @Tags user
func UserRoute(router *gin.RouterGroup) {
	user := new(controllers.UserController)
	router.POST("/user/login", user.Login)
	router.POST("/user/register", user.Register)
	router.GET("/user/auth", middlewares.TokenAuthMiddleware(), user.UserAuth)
	router.GET("/user/verify_email", user.VerifyEmailHandler())
	router.GET("/user/auth/google", user.OpenAuthGoogle)
	router.GET("/user/auth/google/callback",
		user.OpenAuthGoogleCallBack,
		user.InsertOrUpdateWithOpenAuth,
		user.RedirectWithToken,
	)
}
