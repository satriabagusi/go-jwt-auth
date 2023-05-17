/*
Author: Satria Bagus(satria.bagus18@gmail.com)
auth.go (c) 2023
Desc: description
Created:  2023-05-17T09:14:19.129Z
Modified: !date!
*/

package gojwtauth

import (
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("SANGAT_RAHASIA")

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := ctx.GetHeader("Authorization")

		if tokenString == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			ctx.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) { return jwtKey, nil })

		if !token.Valid || err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			ctx.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		ctx.Set("claims", claims)
		ctx.Next()
	}
}

func LoginHandler(ctx *gin.Context) {
	var user User
	if err := ctx.ShouldBind(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// logic authentication (compare username dan password)
	if user.Username == "enigma" && user.Password == "12345" {
		// bikin code untuk generate token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Minute * 1).Unix() // token akan expired dalam 1 menit
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"token": tokenString}) // jika login berhasil, dapatkan token string
	} else {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func ProfileHandler(ctx *gin.Context) {
	// ambil username dari JWT token
	claims := ctx.MustGet("claims").(jwt.MapClaims)
	username := claims["username"].(string)
	// seharusnya return user dari database, tapi di conto ini kita return username
	ctx.JSON(http.StatusOK, gin.H{"username": username})

}
