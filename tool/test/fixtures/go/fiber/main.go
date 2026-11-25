package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	app := fiber.New()
	api := app.Group("/api", protected())
	api.Get("/invoices/:invoiceId", getInvoice)
	app.Post("/auth/login", login)
	app.Listen(":3000")
}

func protected() fiber.Handler { return func(c *fiber.Ctx) error { return c.Next() } }

func login(c *fiber.Ctx) error {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"})
	signed, _ := token.SignedString([]byte("super-secret-key"))
	return c.JSON(fiber.Map{"token": signed})
}

// vulnerable: the repository call never sees the caller
func getInvoice(c *fiber.Ctx) error {
	invoice, err := repo.GetInvoice(c.Params("invoiceId"))
	if err != nil {
		return err
	}
	return c.JSON(invoice)
}
