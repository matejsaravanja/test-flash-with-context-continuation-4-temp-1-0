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