from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from decouple import config
import base64
import logging
from django_ratelimit.decorators import ratelimit
from .models import NFT, User, Transaction
from .utils import verify_craft_token_balance, create_transaction, monitor_transaction, generate_nice_svg  # Import generate_nice_svg
from .serializers import UserSerializer, NFTSerializer, TransactionSerializer #TransactionSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.views.decorators.csrf import csrf_protect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Custom JWT Serializer
class CustomTokenObtainPairSerializer:
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['username'] = user.username
        token['wallet_address'] = user.wallet_address  # Include wallet address
        return token


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='IP', rate='5/m', method='POST')  # Rate limit registration
def register_user(request):
    """
    Registers a new user.
    """
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return Response({'error': 'Rate limit exceeded. Please try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.validated_data['password'] = make_password(serializer.validated_data['password']) #Hash the password.
        serializer.save()
        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Requires authentication
def get_nft_details(request, nft_id):
    """
    Retrieves details of a specific NFT.
    """
    try:
        nft = NFT.objects.get(pk=nft_id)
        serializer = NFTSerializer(nft) #serialize with NFTSerializer
        return Response(serializer.data, status=status.HTTP_200_OK)
    except NFT.DoesNotExist:
        return Response({'error': 'NFT not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception("Error fetching NFT details:")
        return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='IP', rate='10/m', method='POST')
@swagger_auto_schema(
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['wallet_address', 'nft_id', 'amount', 'recipient_public_key'],
        properties={
            'wallet_address': openapi.Schema(type=openapi.TYPE_STRING, description='User\'s wallet address'),
            'nft_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the NFT to purchase'),
            'amount': openapi.Schema(type=openapi.TYPE_STRING, description='Amount to transfer in lamports'),
            'recipient_public_key': openapi.Schema(type=openapi.TYPE_STRING, description='Recipient\'s public key')
        },
    ),
    responses={
        200: openapi.Response(description="Transaction data", schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        400: 'Bad Request',
        404: 'Not Found',
        500: 'Internal Server Error',
    }
)
def initiate_purchase(request):
    """
    Initiates the purchase process by creating a transaction.
    """
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return Response({'error': 'Rate limit exceeded. Please try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    wallet_address = request.data.get('wallet_address')
    nft_id = request.data.get('nft_id')
    amount = request.data.get('amount')  # Amount in lamports for transfer
    recipient_public_key = request.data.get('recipient_public_key')  # Replace with the seller's/app's public key

    if not all([wallet_address, nft_id, amount, recipient_public_key]):
        return Response({'error': 'Missing parameters'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        nft = NFT.objects.get(pk=nft_id)
        user = User.objects.get(wallet_address=wallet_address)
    except NFT.DoesNotExist:
        return Response({'error': 'NFT not found'}, status=status.HTTP_404_NOT_FOUND)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    try:
      amount = int(amount)
    except ValueError:
      return Response({'error': 'Invalid ammount value'}, status=status.HTTP_400_BAD_REQUEST)
    if amount < float(nft.price):
        return Response({'error': 'Amount is less than NFT price'}, status=status.HTTP_400_BAD_REQUEST)

    if not verify_craft_token_balance(wallet_address, amount):
        return Response({'error': 'Insufficient funds'}, status=status.HTTP_400_BAD_REQUEST)

    # Securely retrieve the sender's private key (replace with secure secrets management)
    sender_private_key = config('SENDER_PRIVATE_KEY')
    transaction = create_transaction(base64.b64encode(sender_private_key.encode('utf-8')).decode('utf-8'), recipient_public_key, amount)

    if transaction:
          transaction_data = {
              'recent_blockhash' : transaction.recent_blockhash,
              'fee_payer': str(transaction.fee_payer()),
              'instructions': transaction.instructions
          }
          return Response(transaction_data,status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Transaction creation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='IP', rate='10/m', method='POST')
@swagger_auto_schema(
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['transaction_id', 'wallet_address', 'nft_id'],
        properties={
            'transaction_id': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction ID'),
            'wallet_address': openapi.Schema(type=openapi.TYPE_STRING, description='User\'s wallet address'),
            'nft_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the NFT purchased')
        },
    ),
    responses={
        200: openapi.Response(description="Transaction confirmation message", schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        400: 'Bad Request',
        404: 'Not Found',
        500: 'Internal Server Error',
    }
)
def verify_transaction(request):
    """
    Verifies the transaction and grants access to the NFT upon successful verification.
    """
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return Response({'error': 'Rate limit exceeded. Please try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    serializer = TransactionSerializer(data = request.data)
    serializer.is_valid(raise_exception=True)
    transaction_id = serializer.data.get('transaction_id')
    wallet_address = serializer.data.get('wallet_address')
    nft_id = serializer.data.get('nft_id')


    try:
        transaction_status = monitor_transaction(transaction_id)

        if transaction_status:
            try:
                user = User.objects.get(wallet_address=wallet_address)
                nft = NFT.objects.get(pk=nft_id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            except NFT.DoesNotExist:
                return Response({'error': 'NFT not found'}, status=status.HTTP_404_NOT_FOUND)

            Transaction.objects.create(user=user, nft=nft, transaction_id=transaction_id, craft_amount=nft.price)  # Record transaction
            send_nft_access_email(user.email, nft)
            return Response({'message': 'Transaction Confirmed'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Transaction Failed'}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.exception("Error verifying transaction:")
        return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_nft_content(request, nft_id):
    """
    Retrieves the SVG content of a specific NFT.
    """
    try:
        nft = NFT.objects.get(pk=nft_id)
        return Response({'svg_data': nft.svg_data}, status=status.HTTP_200_OK)
    except NFT.DoesNotExist:
        return Response({'error': 'NFT not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception("Error retrieving NFT content:")
        return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='IP', rate='5/m', method='POST')
@swagger_auto_schema(
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['name', 'description', 'price', 'is_premium'],
        properties={
            'name': openapi.Schema(type=openapi.TYPE_STRING, description='Name of the NFT'),
            'description': openapi.Schema(type=openapi.TYPE_STRING, description='Description of the NFT'),
            'price': openapi.Schema(type=openapi.TYPE_STRING, description='Price of the NFT in lamports'),
            'is_premium': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Is the NFT premium?')
        },
    ),
    responses={
        201: openapi.Response(description="NFT created successfully", schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        400: 'Bad Request',
        500: 'Internal Server Error',
    }
)
def create_nft(request):
    """
    Creates a new NFT.
    """
    was_limited = getattr(request, 'limited', False)

    if was_limited:
        return Response({'error': 'Rate limit exceeded. Please try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = NFTSerializer(data=request.data)
    if serializer.is_valid():
        serializer.validated_data['creator'] = request.user
        serializer.validated_data['svg_data'] = generate_nice_svg()
        serializer.save()
        return Response({'message': 'NFT created successfully', 'nft_id': serializer.data['id']}, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NFTList(generics.ListAPIView):
    """
    Lists all NFTs.
    """
    queryset = NFT.objects.all()
    serializer_class = NFTSerializer
    permission_classes = [IsAuthenticated]


def send_nft_access_email(email, nft):
    """
    Sends an email to the user with access information for the purchased NFT.
    """
    subject = f"Access your Premium NFT: {nft.name}"
    message = f"""
    Congratulations on your purchase!

    You can view your NFT here: http://your-domain.com/nft/{nft.id}

    Download the SVG image here: http://your-domain.com/api/nfts/{nft.id}/content/

    Enjoy!
    """  # Important: Replace with your actual domain
    email_from = config('EMAIL_HOST_USER')
    try:
        send_mail(subject, message, email_from, [email])
        logger.info(f"Email Send to {email} for  NFT {nft.name}")
    except Exception as e:
        logger.error("Error sending email:", exc_info=True)