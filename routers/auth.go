package routers

import (
	"basic-auth-gin/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoute(router *gin.RouterGroup) {
	auth := new(controllers.AuthController)

	// Refresh the token when needed to generate new access_token and refresh_token for the user
	router.POST("/token/refresh", auth.Refresh)
}
