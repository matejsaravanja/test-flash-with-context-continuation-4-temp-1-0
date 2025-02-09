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