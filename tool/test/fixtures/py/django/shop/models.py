from django.db import models


class Order(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)


class Invoice(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
