from rest_framework import serializers

from shop.models import Invoice, Order


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ["id"]


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id"]
