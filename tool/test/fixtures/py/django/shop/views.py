from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from shop.models import Invoice, Order
from shop.serializers import InvoiceSerializer, OrderSerializer


# vulnerable: every order, no owner filter, no object permission
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer


# safe: limited to the caller
class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)


# vulnerable function view
@api_view(["GET"])
def receipt(request, pk):
    order = get_object_or_404(Order, pk=pk)
    return order.receipt


class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return None
