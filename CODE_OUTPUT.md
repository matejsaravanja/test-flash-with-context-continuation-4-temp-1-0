**This file consists of the entire unaltered output for reference.**

Okay, I'm ready to provide the complete, revised code, addressing the security concerns, missing functionalities, and other identified problems in the previous code reviews. I will include all file paths and structure to ensure the application is effortlessly runnable.

**I. Important Security Warning (READ THIS CAREFULLY):**

*   This code significantly improves security compared to previous versions, but it's **still not production-ready without rigorous security audits.**
*   **NEVER EVER** commit your actual `DJANGO_SECRET_KEY` or Solana private keys to version control.  Use a secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager) in production.
*   Carefully review and understand every line of code, especially the authentication, authorization, and input validation logic.

**II. Project Structure:**

```
nft-purchase-app/
├── backend/
│   ├── api/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── serializers.py  # New file
│   │   ├── utils.py
│   │   ├── views.py
│   │   ├── urls.py
│   │   └── tests.py      # New File - Unit Tests
│   ├── core/
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── asgi.py
│   │   └── wsgi.py
│   ├── venv/             # Virtual environment (not committed)
│   ├── manage.py
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.js
│   │   ├── components/
│   │   │   ├── NFTList.js
│   │   │   ├── NFTDetails.js
│   │   │   ├── PurchaseNFT.js
│   │   │   ├── CreateNFT.js
│   │   │   └── RegisterUser.js
│   │   ├── App.css
│   │   ├── index.js
│   │   └── index.css
│   ├── public/
│   │   ├── index.html
│   │   └── ...
│   ├── package.json
│   ├── Dockerfile
│   └── README.md
├── docker-compose.yml
├── .github/workflows/deploy.yml
└── README.md
```

**III. Backend Implementation:**

*   **backend/requirements.txt**

```text
django
djangorestframework
psycopg2-binary
python-decouple
solana
web3
requests
djangorestframework-simplejwt
django-ratelimit
drf-yasg  # For Swagger documentation
```

    Run `pip install -r requirements.txt` to update dependencies.

*   **backend/core/settings.py**

```python
import os
from decouple import config
from pathlib import Path
from datetime import timedelta #For JWT refresh token

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('DJANGO_SECRET_KEY', default='your_secret_key_here', cast=str)  # NEVER hardcode in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = ['*']  # Restrict in production!

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',  # JWT authentication
    'ratelimit',  # Rate limiting
    'drf_yasg',  # Swagger
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'ratelimit.middleware.RatelimitMiddleware',  # Rate limiting
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='nft_db', cast=str),
        'USER': config('DB_USER', default='nft_user', cast=str),
        'PASSWORD': config('DB_PASSWORD', default='nft_password', cast=str),
        'HOST': config('DB_HOST', default='db', cast=str),  # Important for Docker
        'PORT': config('DB_PORT', default=5432, cast=int),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# JWT settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',  # Require authentication by default
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', cast=int)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True

# Rate limiting settings
RATELIMIT_USE_CACHE = True
RATELIMIT_CACHE = 'default'  # Use Django's default cache
RATELIMIT_ENABLE = True  # Enable rate limiting

# Set the key format to include the method
RATELIMIT_KEY_FORMAT = '%(rate)s:%(method)s:%(user_or_ip)s'

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',  # For demonstration purposes
    }
}
```

*   **backend/core/urls.py**

```python
from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="NFT Purchase API",
        default_version='v1',
        description="API for purchasing premium NFTs",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="contact@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('api/token/', include('rest_framework_simplejwt.urls')),  # JWT endpoints
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
```

*   **backend/api/models.py**

```python
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    wallet_address = models.CharField(max_length=64, unique=True, blank=True, null=True)  # Make this optional
    # Removed email unique constraint
    email = models.EmailField(blank=True, null=True) #Removed unique constraint for now.

    def __str__(self):
        return self.username  # Use username instead of wallet_address


class NFT(models.Model):
    svg_data = models.TextField()
    name = models.CharField(max_length=255)
    description = models.TextField()
    creator = models.ForeignKey(User, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=19, decimal_places=10, default=0.0)
    is_premium = models.BooleanField(default=False)

    class Meta:
        unique_together = ('name', 'creator')

    def __str__(self):
        return self.name


class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    nft = models.ForeignKey(NFT, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    craft_amount = models.DecimalField(max_digits=19, decimal_places=10)
    transaction_id = models.CharField(max_length=128)

    def __str__(self):
        return f"Transaction {self.pk} - User: {self.user.username}, NFT: {self.nft.name}"
```

*   **backend/api/serializers.py**

```python
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
```

*   **backend/api/utils.py**

```python
from solana.rpc.api import Client
from solana.publickey import PublicKey
from decouple import config
from solana.transaction import Transaction, AccountMeta, TransactionInstruction
from solana.system_program import TransferRequest
from solana.keypair import Keypair
import base64
import logging
import requests
import random

logger = logging.getLogger(__name__)

SOLANA_NETWORK = config('SOLANA_NETWORK')
CRAFT_TOKEN_MINT_ADDRESS = config('CRAFT_TOKEN_MINT_ADDRESS')

# Assuming SPL token program ID
SPL_TOKEN_PROGRAM_ID = PublicKey("TokenkegQfeZyiNwmdzQVZH3t7317XzWHk9E2tJB4Wj")

def get_associated_token_address(wallet_address, token_mint_address):
    """
    Derives the associated token account address for a given wallet and token mint.
    """
    try:
        from spl.token.associated_token_account import get_associated_token_address as gata
        return gata(PublicKey(wallet_address), PublicKey(token_mint_address))
    except ImportError:
        logger.error("Please install the spl-token package: pip install spl-token")
        return None

def verify_craft_token_balance(wallet_address, amount_required):
    """
    Verifies if the given wallet has enough CRAFT tokens using the Solana blockchain.
    """
    try:
        solana_client = Client(SOLANA_NETWORK)
        public_key = PublicKey(wallet_address)

        # Get the associated token account address
        associated_token_address = get_associated_token_address(public_key, CRAFT_TOKEN_MINT_ADDRESS)

        if associated_token_address is None:
            logger.error("Could not derive associated token address.")
            return False

        # Get token account balance
        try:
            balance_info = solana_client.get_token_account_balance(associated_token_address)
            balance = balance_info.value.amount if balance_info and balance_info.value else 0
            balance = int(balance)
          #  print(f"Wallet {wallet_address} has {balance} CRAFT tokens. Required: {amount_required}") #debugging
            if balance >= amount_required:
                return True
            else:
                return False
        except Exception as e:
            logger.exception(f"Error fetching token balance for {associated_token_address}:")
            return False

    except Exception as e:
        logger.exception("Error verifying CRAFT balance:")
        return False


def create_transaction(sender_private_key, recipient_public_key, amount):
    """
    Creates a Solana transaction to transfer tokens.
    """
    try:
        solana_client = Client(SOLANA_NETWORK)
        sender_keypair = Keypair.from_secret_key(base64.b64decode(sender_private_key))
        recipient_public_key = PublicKey(recipient_public_key)

        # Get the recent blockhash
        recent_blockhash = solana_client.get_latest_blockhash().value.blockhash

        # Create a transfer instruction
        transfer_instruction = TransferRequest(
            from_pubkey=sender_keypair.public_key,
            to_pubkey=recipient_public_key,
            lamports=amount
        )

        # Create a transaction and add the transfer instruction
        transaction = Transaction()
        transaction.add(transfer_instruction)

        # Set the recent blockhash
        transaction.recent_blockhash = recent_blockhash

        # Set the fee payer
        transaction.fee_payer = sender_keypair.public_key

        # Sign the transaction
        transaction.sign(sender_keypair)

        return transaction
    except Exception as e:
        logger.exception("Error creating transaction:")
        return None


def monitor_transaction(transaction_id):
    """
    Monitors a Solana transaction for confirmation.
    """
    try:
        solana_client = Client(SOLANA_NETWORK)
        result = solana_client.get_transaction(transaction_id)
        if result and result.value and result.value.meta and result.value.meta.err is None:
            return True
        else:
            return False
    except Exception as e:
        logger.exception("Error monitoring transaction:")
        return False


def generate_nice_svg():
    """
    Generates a "nicer" SVG image.
    """
    width = 200
    height = 200
    colors = ['#FF5733', '#33FF57', '#3357FF', '#FFFF33', '#FF33FF', '#33FFFF'] #Nice Colors
    num_circles = random.randint(3, 7)  # Random number of circles

    svg = f'<svg width="{width}" height="{height}">'
    svg += f'<rect width="{width}" height="{height}" fill="{random.choice(colors)}"/>' #background

    for _ in range(num_circles):
        cx = random.randint(20, width - 20)
        cy = random.randint(20, height - 20)
        r = random.randint(10, 30)
        fill = random.choice(colors)
        svg += f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}" opacity="0.7"/>'

    svg += '</svg>'
    return svg
```

*   **backend/api/views.py**

```python
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
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
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
            'is_premium': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Is the NFT premium?'),
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
```

*   **backend/api/urls.py**

```python
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
```

*   **backend/api/tests.py**

```python
from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from .models import NFT
from decouple import config
import base64
from .utils import verify_craft_token_balance

class UserRegistrationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.registration_url = reverse('register_user')
        User = get_user_model()
        self.test_user = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'test@example.com',
            'wallet_address': 'testwalletaddress'
        }
    def test_register_user(self):
         response = self.client.post(self.registration_url, self.test_user, content_type='application/json')
         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
         self.assertEqual(get_user_model().objects.count(), 1)
         registered_user = get_user_model().objects.first()
         self.assertEqual(registered_user.username, self.test_user['username'])
         self.assertTrue(registered_user.check_password(self.test_user['password']))

class CraftTokenBalanceTest(TestCase):
  def test_verify_craft_token_balance_sufficient(self):
    wallet_address = config('WALLET_ADDRESS')
    amount_required = 1000
    result = verify_craft_token_balance(wallet_address, amount_required)
    self.assertTrue(result)

  def test_verify_craft_token_balance_insufficient(self):
    wallet_addressOkay, I understand. I will combine the code from the initial iteration and incorporate the improvements suggested in the code review to produce a fully functional code. I will also retain all the explanations/comments from the previous iterations to ensure clarity.

Please provide the initial code and the code review so I can finalize the code.
