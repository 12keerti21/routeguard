package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var db *gorm.DB

type User struct {
	ID       uint   `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Order struct {
	ID     uint   `json:"id"`
	UserID uint   `json:"user_id"`
	Item   string `json:"item"`
}

func Register(g *gin.RouterGroup) {
	g.GET("/:id", GetOrder)
	g.GET("/:id/safe", GetOrderSafe)
	g.DELETE("/:id", DeleteOrder)
}

func AuthRequired() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
func RequireAdmin() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
func Login(c *gin.Context)          {}
func Stats(c *gin.Context)          {}

// vulnerable: any signed-in user reads any order
func GetOrder(c *gin.Context) {
	id := c.Param("id")
	var order Order
	db.First(&order, id)
	c.JSON(http.StatusOK, order)
}

// safe: scoped to the caller
func GetOrderSafe(c *gin.Context) {
	id := c.Param("id")
	userID := c.GetUint("userID")
	var order Order
	db.Where("id = ? AND user_id = ?", id, userID).First(&order)
	c.JSON(http.StatusOK, order)
}

// vulnerable, through a service function
func DeleteOrder(c *gin.Context) {
	removeOrder(c.Param("id"))
	c.Status(http.StatusNoContent)
}

func removeOrder(id string) {
	db.Where("id = ?", id).Delete(&Order{})
}

// vulnerable: role comes from the body
func UpdateProfile(c *gin.Context) {
	var user User
	c.ShouldBindJSON(&user)
	db.Save(&user)
}

// vulnerable: password goes back
func Profile(c *gin.Context) {
	var user User
	db.First(&user, c.GetUint("userID"))
	c.JSON(http.StatusOK, user)
}
