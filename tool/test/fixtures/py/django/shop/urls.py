from django.urls import path
from rest_framework.routers import DefaultRouter

from shop import views

router = DefaultRouter()
router.register(r"orders", views.OrderViewSet)
router.register(r"invoices", views.InvoiceViewSet)

urlpatterns = [
    path("orders/<int:pk>/receipt/", views.receipt),
    path("public/", views.PublicView.as_view()),
    *router.urls,
]
