from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import NFT

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = get_user_model()
        fields = ('id', 'username', 'password', 'email', 'wallet_address') #Added wallet address

    def create(self, validated_data):
        user = get_user_model().objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data.get('email', ''),
            wallet_address=validated_data.get('wallet_address',None) #Added wallet address
        )
        return user


class NFTSerializer(serializers.ModelSerializer):
    class Meta:
        model = NFT
        fields = '__all__'
        read_only_fields = ('creator', 'svg_data')  # Creator is set in view, SVG generated


class TransactionSerializer(serializers.Serializer):
    transaction_id = serializers.CharField(max_length=128)
    wallet_address = serializers.CharField(max_length=64)
    nft_id = serializers.IntegerField()