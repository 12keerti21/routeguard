package main

import (
	"github.com/gin-gonic/gin"

	"example.com/ginapp/handlers"
)

func main() {
	r := gin.Default()
	api := r.Group("/api")
	api.POST("/login", handlers.Login)
	api.Use(handlers.AuthRequired())
	handlers.Register(api.Group("/orders"))
	api.PUT("/profile", handlers.UpdateProfile)
	api.GET("/profile", handlers.Profile)
	admin := api.Group("/admin", handlers.RequireAdmin())
	admin.GET("/stats", handlers.Stats)
	api.GET("/metrics", handlers.Stats)
	r.Run()
}
