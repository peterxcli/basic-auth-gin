package middlewares

import (
	"basic-auth-gin/controllers"

	"github.com/gin-gonic/gin"
)

var auth = new(controllers.AuthController)

// TokenAuthMiddleware validates the access_token in the header of each request that needs authentication
// and is attached as a middleware function to the gin router
// JWT Authentication middleware attached to each request that needs to be authenticated to validate the access_token in the header
// @Summary JWT Authentication middleware
// @Description Validates the access_token in the header of each request that needs to be authenticated
// @Accept json
// @Produce json
// @Success 200 {string} string "OK"
// @Failure 401 {string} string "Unauthorized"
// @Failure 406 {string} string "Not Acceptable"
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth.TokenValid(c)
		c.Next()
	}
}
