package api

import (
	"mgo-gin/app/form"
	"mgo-gin/app/repository"
	"mgo-gin/db"
	"mgo-gin/middlewares"
	"mgo-gin/utils/bcrypt"
	err2 "mgo-gin/utils/err"
	"net/http"

	"github.com/gin-gonic/gin"
)

func ApplyUserAPI(app *gin.RouterGroup, resource *db.Resource) {
	userEntity := repository.NewUserEntity(resource)
	authRoute := app.Group("")
	authRoute.POST("/login", login(userEntity))
	authRoute.POST("/sign-up", signUp(userEntity))

	userRoute := app.Group("/users")
	userRoute.GET("", getAllUSer(userEntity)) // when need authorization
	// userRoute.GET("", getAllUSer(userEntity))
	userRoute.GET("/:username", getUserByUsername(userEntity))
	userRoute.DELETE("/:username", removeUserByUsername(userEntity))
}

func login(userEntity repository.IUser) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {

		userRequest := form.User{}
		if err := ctx.Bind(&userRequest); err != nil {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}

		user, code, _ := userEntity.GetOneByUsername(userRequest.Username)

		if (user == nil) || bcrypt.ComparePasswordAndHashedPassword(userRequest.Password, user.Password) != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"err": "Wrong username or password"})
			return
		}
		token := middlewares.GenerateJWTToken(*user)
		response := map[string]interface{}{
			"token": token,
			"error": nil,
		}
		ctx.JSON(code, response)
	}
}

func signUp(userEntity repository.IUser) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {

		userRequest := form.User{}
		if err := ctx.Bind(&userRequest); err != nil {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}
		user, code, err := userEntity.CreateOne(userRequest)
		response := map[string]interface{}{
			"user":  user,
			"error": err2.GetErrorMessage(err),
		}
		ctx.JSON(code, response)
	}
}

// GetAllUser godoc
// @Tags UserController
// @Summary Get all user
// @Description Get all user
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
// @Success 200 {array} model.User
// @Router /user [get]
func getAllUSer(userEntity repository.IUser) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		list, code, err := userEntity.GetAll()
		response := map[string]interface{}{
			"users": list,
			"error": err2.GetErrorMessage(err),
		}
		ctx.JSON(code, response)
	}
}

func getUserByUsername(userEntity repository.IUser) func(ctc *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.Param("username")
		user, code, err := userEntity.GetOneByUsername(id)
		response := map[string]interface{}{
			"user": user,
			"err":  err2.GetErrorMessage(err),
		}
		ctx.JSON(code, response)
	}
}

func removeUserByUsername(userEntity repository.IUser) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.Param("username")
		code, err := userEntity.DeleteOneByUsername(id)

		response := map[string]interface{}{
			"err": err2.GetErrorMessage(err),
		}
		ctx.JSON(code, response)
	}
}
