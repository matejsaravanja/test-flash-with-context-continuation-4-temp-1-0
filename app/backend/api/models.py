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