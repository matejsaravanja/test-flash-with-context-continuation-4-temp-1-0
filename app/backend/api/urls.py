from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user, name='register_user'),
    path('token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('nfts/<int:nft_id>/', views.get_nft_details, name='get_nft_details'),
    path('purchase/', views.initiate_purchase, name='initiate_purchase'),
    path('verify_transaction/', views.verify_transaction, name='verify_transaction'),
    path('nfts/<int:nft_id>/content/', views.get_nft_content, name='get_nft_content'),
    path('create_nft/', views.create_nft, name='create_nft'),
    path('nfts/', views.NFTList.as_view(), name='nft_list'),  # Add this line
]