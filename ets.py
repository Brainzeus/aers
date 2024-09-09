import asyncio
import hashlib
import json
import time
import random
import string
from decimal import Decimal
from typing import List, Dict, Any, Set, Optional, Union
from collections import defaultdict
import logging
import base58
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
import websockets
import ssl
import os
import sys
from fractions import Fraction
import aiosqlite
from aiohttp import web

# Configurare logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constante globale
MAX_TRANSACTIONS_PER_BLOCK = 10000
TARGET_BLOCK_TIME = Fraction(3, 10000000)  # 0.0000003 secunde
INITIAL_BRAINERS_SUPPLY = Fraction(5000000000, 1)
MIN_FEE = Fraction(1, 1000)  # 0.001 BRAINERS
MAX_FEE = Fraction(1, 100)   # 0.01 BRAINERS
GIFT_VALIDATOR_BURN = Fraction(6000, 1)  # 6000 BRAINERS
MIN_LIQUIDITY_DEX = Fraction(1000, 1)  # 1 milion BRAINERS
MIN_LIQUIDITY_TTF = Fraction(500000, 1)  # 500k BRAINERS

class BrainersJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Fraction):
            return str(obj)
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, Validator):
            return obj.to_dict()
        if isinstance(obj, Token):
            return obj.to_dict()
        if isinstance(obj, SmartContract):
            return obj.to_dict()
        return super().default(obj)

class Transaction:
    def __init__(self, sender: str, recipient: str, amount: Fraction, transaction_type: str, fee: Fraction, data: Dict[str, Any] = None, signature: str = None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.transaction_type = transaction_type
        self.fee = fee
        self.data = data or {}
        self.signature = signature
        self.timestamp = time.time()
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        transaction_data = f"{self.sender}{self.recipient}{self.amount}{self.transaction_type}{self.fee}{json.dumps(self.data, sort_keys=True)}{self.timestamp}"
        return hashlib.sha256(transaction_data.encode()).hexdigest()

    def sign(self, private_key: ec.EllipticCurvePrivateKey):
        transaction_data = self.calculate_hash().encode()
        self.signature = base58.b58encode(private_key.sign(
            transaction_data,
            ec.ECDSA(hashes.SHA256())
        )).decode()

    def verify_signature(self, public_key: ec.EllipticCurvePublicKey) -> bool:
        try:
            signature = base58.b58decode(self.signature)
            transaction_data = self.calculate_hash().encode()
            public_key.verify(
                signature,
                transaction_data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": str(self.amount),
            "transaction_type": self.transaction_type,
            "fee": str(self.fee),
            "data": self.data,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, data):
        tx = cls(
            data['sender'],
            data['recipient'],
            Fraction(data['amount']),
            data['transaction_type'],
            Fraction(data['fee']),
            data.get('data'),
            data['signature']
        )
        tx.timestamp = data['timestamp']
        tx.hash = data['hash']
        return tx

class Block:
    def __init__(self, index: int, transactions: List[Transaction], timestamp: float, previous_hash: str, validator: str):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.validator = validator
        self.merkle_root = self.calculate_merkle_root()
        self.hash = self.calculate_hash()

    def calculate_merkle_root(self):
        if not self.transactions:
            return hashlib.sha256(b"").hexdigest()
        transaction_hashes = [tx.hash for tx in self.transactions]
        while len(transaction_hashes) > 1:
            new_hashes = []
            for i in range(0, len(transaction_hashes), 2):
                if i + 1 < len(transaction_hashes):
                    combined_hash = hashlib.sha256((transaction_hashes[i] + transaction_hashes[i+1]).encode()).hexdigest()
                else:
                    combined_hash = hashlib.sha256((transaction_hashes[i] + transaction_hashes[i]).encode()).hexdigest()
                new_hashes.append(combined_hash)
            transaction_hashes = new_hashes
        return transaction_hashes[0]

    def calculate_hash(self):
        block_data = {
            "index": self.index,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "validator": self.validator
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "validator": self.validator,
            "merkle_root": self.merkle_root,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, data):
        transactions = [Transaction.from_dict(tx) for tx in data['transactions']]
        block = cls(data['index'], transactions, data['timestamp'], data['previous_hash'], data['validator'])
        block.merkle_root = data['merkle_root']
        block.hash = data['hash']
        return block

class Token:
    def __init__(self, name: str, symbol: str, total_supply: Fraction, creator: str, is_minable: bool = False, difficulty: int = 0):
        self.name = name
        self.symbol = symbol
        self.total_supply = total_supply
        self.circulating_supply = Fraction(0)
        self.creator = creator
        self.is_minable = is_minable
        self.difficulty = difficulty
        self.address = self.generate_address()
        self.holders = defaultdict(Fraction)

    def generate_address(self):
        token_data = f"{self.name}{self.symbol}{self.total_supply}{self.creator}{time.time()}"
        token_hash = hashlib.sha256(token_data.encode()).hexdigest()
        return f"0xBrainers{token_hash[:34]}"

    def mint(self, amount: Fraction, recipient: str):
        if self.circulating_supply + amount > self.total_supply:
            raise ValueError("Minting would exceed total supply")
        self.circulating_supply += amount
        self.holders[recipient] += amount

    def burn(self, amount: Fraction, holder: str):
        if self.holders[holder] < amount:
            raise ValueError("Insufficient balance to burn")
        self.holders[holder] -= amount
        self.circulating_supply -= amount

    def transfer(self, sender: str, recipient: str, amount: Fraction):
        if self.holders[sender] < amount:
            raise ValueError("Insufficient balance to transfer")
        self.holders[sender] -= amount
        self.holders[recipient] += amount

    def to_dict(self):
        return {
            "name": self.name,
            "symbol": self.symbol,
            "total_supply": str(self.total_supply),
            "circulating_supply": str(self.circulating_supply),
            "creator": self.creator,
            "is_minable": self.is_minable,
            "difficulty": self.difficulty,
            "address": self.address
        }

class Wallet:
    def __init__(self, private_key=None):
        if private_key:
            self.private_key = ec.derive_private_key(int.from_bytes(base58.b58decode(private_key), byteorder='big'), ec.SECP256R1(), default_backend())
        else:
            self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.address = self.generate_address()
        self.balances = defaultdict(Fraction)
        self.imported_tokens = set()

    def generate_address(self):
        public_bytes = self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        address_hash = hashlib.sha256(public_bytes).digest()
        return f"0xBrainers{base58.b58encode(address_hash).decode()[:34]}"

    def get_private_key(self):
        return base58.b58encode(self.private_key.private_numbers().private_value.to_bytes(32, byteorder='big')).decode()

    def sign_transaction(self, transaction_data: str):
        signature = self.private_key.sign(
            transaction_data.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return base58.b58encode(signature).decode()

    def import_token(self, token_address: str):
        self.imported_tokens.add(token_address)

    def to_dict(self):
        return {
            "address": self.address,
            "balances": {token: str(balance) for token, balance in self.balances.items()},
            "imported_tokens": list(self.imported_tokens)
        }

class Validator:
    def __init__(self, address: str, stake: Fraction, is_permanent: bool = False):
        self.address = address
        self.stake = stake
        self.is_permanent = is_permanent
        self.last_block_validated = 0
        self.reputation = Fraction(1)
        self.is_active = True
        self.total_rewards = Fraction(0)
        self.performance_history = []

    def update_reputation(self, performance: Fraction):
        self.reputation = (self.reputation * Fraction(9, 10)) + (performance * Fraction(1, 10))
        self.performance_history.append((time.time(), performance))
        if len(self.performance_history) > 1000:
            self.performance_history.pop(0)

    def add_reward(self, amount: Fraction):
        self.total_rewards += amount

    def to_dict(self):
        return {
            "address": self.address,
            "stake": str(self.stake),
            "is_permanent": self.is_permanent,
            "last_block_validated": self.last_block_validated,
            "reputation": str(self.reputation),
            "is_active": self.is_active,
            "total_rewards": str(self.total_rewards),
            "average_performance": str(sum(p[1] for p in self.performance_history) / len(self.performance_history)) if self.performance_history else "0"
        }

class SmartContract:
    def __init__(self, address: str, creator: str, code: str, abi: Dict[str, Any]):
        self.address = address
        self.creator = creator
        self.code = code
        self.abi = abi
        self.storage = {}

    async def execute(self, method: str, params: Dict[str, Any], context: 'ExecutionContext') -> Any:
        if method not in self.abi:
            raise ValueError(f"Method {method} not found in contract ABI")

        global_vars = {
            "storage": self.storage,
            "context": context,
            "params": params
        }
        exec(self.code, global_vars)
        result = await global_vars[method](**params)
        return result

    def to_dict(self):
        return {
            "address": self.address,
            "creator": self.creator,
            "abi": self.abi
        }

class DEX:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.liquidity_pools = defaultdict(lambda: {'BRAINERS': Fraction(0), 'TOKEN': Fraction(0)})
        self.orders = defaultdict(list)
        self.trading_start_times = {}
        self.chat_messages = defaultdict(list)
        self.trading_pairs = set()
        self.fee_percentage = Fraction(3, 1000)  # 0.3% fee

    async def add_liquidity(self, token_address: str, brainers_amount: Fraction, token_amount: Fraction, provider: str, lock_time: int):
        if self.liquidity_pools[token_address]['BRAINERS'] + brainers_amount < MIN_LIQUIDITY_DEX:
            return False, "Insufficient liquidity"

        self.liquidity_pools[token_address]['BRAINERS'] += brainers_amount
        self.liquidity_pools[token_address]['TOKEN'] += token_amount

        if token_address not in self.trading_start_times:
            self.trading_start_times[token_address] = time.time() + 24 * 60 * 60  # Start trading after 24 hours

        self.trading_pairs.add((token_address, 'BRAINERS'))

        # Create a liquidity provider transaction
        lp_tx = Transaction(
            sender=provider,
            recipient=self.blockchain.dex_address,
            amount=brainers_amount,
            transaction_type="add_liquidity",
            fee=self.blockchain.calculate_transaction_fee(brainers_amount),
            data={
                'token_address': token_address,
                'token_amount': str(token_amount),
                'lock_time': lock_time
            }
        )
        await self.blockchain.add_transaction(lp_tx)

        return True, "Liquidity added successfully"

    async def remove_liquidity(self, token_address: str, liquidity_amount: Fraction, provider: str):
        pool = self.liquidity_pools[token_address]
        total_liquidity = pool['BRAINERS'] + pool['TOKEN']
        
        brainers_to_return = (liquidity_amount / total_liquidity) * pool['BRAINERS']
        tokens_to_return = (liquidity_amount / total_liquidity) * pool['TOKEN']

        pool['BRAINERS'] -= brainers_to_return
        pool['TOKEN'] -= tokens_to_return

        # Create a liquidity removal transaction
        remove_lp_tx = Transaction(
            sender=self.blockchain.dex_address,
            recipient=provider,
            amount=brainers_to_return,
            transaction_type="remove_liquidity",
            fee=Fraction(0),
            data={
                'token_address': token_address,
                'token_amount': str(tokens_to_return)
            }
        )
        await self.blockchain.add_transaction(remove_lp_tx)

        return True, f"Removed {brainers_to_return} BRAINERS and {tokens_to_return} tokens from liquidity pool"

    async def place_order(self, token_address: str, order_type: str, amount: Fraction, price: Fraction, trader: str):
        if time.time() < self.trading_start_times.get(token_address, 0):
            return False, "Trading has not started for this token"

        order = {
            'trader': trader,
            'type': order_type,
            'amount': amount,
            'price': price,
            'timestamp': time.time()
        }
        self.orders[token_address].append(order)

        # Create an order placement transaction
        order_tx = Transaction(
            sender=trader,
            recipient=self.blockchain.dex_address,
            amount=Fraction(0),
            transaction_type="place_order",
            fee=self.blockchain.calculate_transaction_fee(Fraction(0)),
            data={
                'token_address': token_address,
                'order_type': order_type,
                'amount': str(amount),
                'price': str(price)
            }
        )
        await self.blockchain.add_transaction(order_tx)

        await self.match_orders(token_address)
        return True, "Order placed successfully"

    async def match_orders(self, token_address: str):
        buy_orders = sorted([o for o in self.orders[token_address] if o['type'] == 'buy'], key=lambda x: x['price'], reverse=True)
        sell_orders = sorted([o for o in self.orders[token_address] if o['type'] == 'sell'], key=lambda x: x['price'])

        while buy_orders and sell_orders and buy_orders[0]['price'] >= sell_orders[0]['price']:
            buy_order = buy_orders[0]
            sell_order = sell_orders[0]

            trade_price = (buy_order['price'] + sell_order['price']) / 2
            trade_amount = min(buy_order['amount'], sell_order['amount'])

            # Execute the trade
            await self.execute_trade(token_address, buy_order['trader'], sell_order['trader'], trade_amount, trade_price)

            # Update orders
            buy_order['amount'] -= trade_amount
            sell_order['amount'] -= trade_amount

            if buy_order['amount'] == 0:
                buy_orders.pop(0)
            if sell_order['amount'] == 0:
                sell_orders.pop(0)

        # Update the order book
        self.orders[token_address] = buy_orders + sell_orders

    async def execute_trade(self, token_address: str, buyer: str, seller: str, amount: Fraction, price: Fraction):
        brainers_amount = amount * price
        fee = brainers_amount * self.fee_percentage

        # Create a trade execution transaction
        trade_tx = Transaction(
            sender=self.blockchain.dex_address,
            recipient=self.blockchain.dex_address,
            amount=Fraction(0),
            transaction_type="execute_trade",
            fee=fee,
            data={
                'token_address': token_address,
                'buyer': buyer,
                'seller': seller,
                'token_amount': str(amount),
                'brainers_amount': str(brainers_amount)
            }
        )
        await self.blockchain.add_transaction(trade_tx)

        # Update balances (this should be done in the blockchain's apply_transaction method)
        self.blockchain.accounts[buyer][token_address] += amount
        self.blockchain.accounts[buyer]['BRAINERS'] -= brainers_amount + fee/2
        self.blockchain.accounts[seller][token_address] -= amount
        self.blockchain.accounts[seller]['BRAINERS'] += brainers_amount - fee/2

    async def add_chat_message(self, token_address: str, sender: str, message: str):
        chat_tx = Transaction(
            sender=sender,
            recipient=self.blockchain.dex_address,
            amount=Fraction(0),
            transaction_type="chat_message",
            fee=self.blockchain.calculate_transaction_fee(Fraction(0)),
            data={
                'token_address': token_address,
                'message': message
            }
        )
        await self.blockchain.add_transaction(chat_tx)

        self.chat_messages[token_address].append({
            'sender': sender,
            'message': message,
            'timestamp': time.time()
        })

    def get_order_book(self, token_address: str):
        return {
            'buy_orders': [o for o in self.orders[token_address] if o['type'] == 'buy'],
            'sell_orders': [o for o in self.orders[token_address] if o['type'] == 'sell']
        }

    def get_chat_messages(self, token_address: str, limit: int = 100):
        return self.chat_messages[token_address][-limit:]

    def get_liquidity_pool_info(self, token_address: str):
        pool = self.liquidity_pools[token_address]
        return {
            'brainers': str(pool['BRAINERS']),
            'token': str(pool['TOKEN']),
            'total_liquidity': str(pool['BRAINERS'] + pool['TOKEN'])
        }

class Blockchain:
    def __init__(self, total_supply: Fraction):
        self.chain = []
        self.pending_transactions = []
        self.accounts = defaultdict(lambda: defaultdict(Fraction))
        self.tokens = {}
        self.validators = {}
        self.smart_contracts = {}
        self.total_supply = total_supply
        self.dex = DEX(self)
        self.dex_address = "0xBrainersDEX"
        self.min_stake = Fraction(10000, 1)
        self.block_time = TARGET_BLOCK_TIME
        self.db_connection = None
        self.mempool = []
        self.state_root = None
        self.permanent_validator = None
        self.network_code = self.load_or_generate_network_code()

    def load_or_generate_network_code(self):
        if os.path.exists('network_code.txt'):
            with open('network_code.txt', 'r') as f:
                return f.read().strip()
        else:
            network_code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            with open('network_code.txt', 'w') as f:
                f.write(network_code)
            return network_code

    async def initialize_database(self):
        self.db_connection = await aiosqlite.connect('brainers_blockchain.db')
        await self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                hash TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                hash TEXT PRIMARY KEY,
                block_hash TEXT,
                data TEXT
            )
        ''')
        await self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                address TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                address TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS validators (
                address TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS smart_contracts (
                address TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self.db_connection.commit()

    async def create_genesis_block(self):
        # Permanent validator address fix
        self.permanent_validator = Validator("0xBrainers6gEWBMbitCTidhikgwko5djKMxkpE1jPaV", self.total_supply / 10, is_permanent=True)
        self.validators[self.permanent_validator.address] = self.permanent_validator

        genesis_transactions = self.create_initial_distribution()
        genesis_block = Block(
            index=0,
            transactions=genesis_transactions,
            timestamp=time.time(),
            previous_hash="0" * 64,
            validator=self.permanent_validator.address
        )
        self.chain.append(genesis_block)
        await self.save_block(genesis_block)
        self.state_root = self.calculate_state_root()
        logger.info("Genesis block created")

    def create_initial_distribution(self) -> List[Transaction]:
        # Predefined wallet allocations
        allocations = [
            ("0xBrainersEKEs23zsvUp7dHx5r8oc7ydw7SXzfNAbhi", Fraction(371000000, 1), "Rezerva"),
            ("0xBrainersASQ2abrQ5dVVxpf4fj2fJB5JVa9qFdsZ5k", Fraction(950000000, 1), "Lichiditate"),
            ("0xBrainersKAXDHeGdhPbLtE7cj9CAsiv6G8JAZgBtMf", Fraction(950000000, 1), "Rez_stable_coin"),
            ("0xBrainersEn5mYsZDU5c5NmAkVv6XpPcMNUPgtDuWAT", Fraction(1000000000, 1), "Investitori_P"),
            ("0xBrainers5Uej2Brz4heihbGwZMivSxnsdMEy9fZmXv", Fraction(950000000, 1), "Garantie"),
            ("0xBrainers6kzpxp4cCBMRtRc3GnHWKnCdTJrYc13xSq", Fraction(279000000, 1), "Farming")
        ]

        transactions = []
        for address, amount, category in allocations:
            transaction = Transaction(
                sender="0" * 40,  # Genesis transaction
                recipient=address,
                amount=amount,
                transaction_type="genesis",
                fee=Fraction(0),
                signature=""  # Genesis transactions are not signed
            )
            transactions.append(transaction)
            self.accounts[address]["BRAINERS"] += amount
            logger.info(f"Allocated {amount} BRAINERS to {category} wallet: {address}")
        
        return transactions

    def calculate_transaction_fee(self, amount: Fraction) -> Fraction:
        base_fee = MIN_FEE
        fee_multiplier = Fraction(3, 2) ** (len(self.pending_transactions) // 1000)
        fee = min(max(base_fee * fee_multiplier, MIN_FEE), MAX_FEE)
        return fee

    async def add_transaction(self, transaction: Transaction) -> bool:
        if transaction.data.get('network_code') != self.network_code:
            logger.error("Invalid network code in transaction")
            return False

        if transaction.transaction_type != "genesis":
            if self.accounts[transaction.sender][transaction.data.get('token', 'BRAINERS')] < transaction.amount + transaction.fee:
                logger.error(f"Insufficient balance for sender {transaction.sender}")
                return False

        if not self.verify_transaction(transaction):
            logger.error(f"Invalid transaction signature for transaction {transaction.hash}")
            return False

        self.mempool.append(transaction)
        return True

    def verify_transaction(self, transaction: Transaction) -> bool:
        if transaction.transaction_type == "genesis":
            return True
        try:
            public_key = ec.derive_public_key_from_private(transaction.sender)
            return transaction.verify_signature(public_key)
        except:
            return False

    async def create_block(self) -> Optional[Block]:
        validator = self.select_validator()
        if not validator:
            logger.error(f"No active validators available")
            return None

        transactions = self.mempool[:MAX_TRANSACTIONS_PER_BLOCK]
        new_block = Block(
            index=len(self.chain),
            transactions=transactions,
            timestamp=time.time(),
            previous_hash=self.chain[-1].hash if self.chain else "0" * 64,
            validator=validator.address
        )

        for tx in transactions:
            await self.apply_transaction(tx)

        self.chain.append(new_block)
        await self.save_block(new_block)
        self.mempool = self.mempool[MAX_TRANSACTIONS_PER_BLOCK:]

        # Reward for validator
        reward_tx = Transaction(
            sender="0" * 40,
            recipient=validator.address,
            amount=self.calculate_block_reward(),
            transaction_type="reward",
            fee=Fraction(0),
            signature=""
        )
        await self.apply_transaction(reward_tx)

        validator.update_reputation(Fraction(1))  # Assume successful validation
        validator.last_block_validated = new_block.index

        self.state_root = self.calculate_state_root()

        return new_block

    def select_validator(self) -> Optional[Validator]:
        if self.permanent_validator.is_active:
            return self.permanent_validator

        eligible_validators = [v for v in self.validators.values() if v.stake >= self.min_stake and v.is_active]
        
        if not eligible_validators:
            return None

        total_stake = sum(v.stake * v.reputation for v in eligible_validators)
        selection_point = random.uniform(0, float(total_stake))
        current_point = Fraction(0)

        for validator in eligible_validators:
            current_point += validator.stake * validator.reputation
            if current_point >= selection_point:
                return validator

        return eligible_validators[-1]  # Fallback to last validator if something goes wrong

    async def apply_transaction(self, transaction: Transaction):
        token = transaction.data.get('token', 'BRAINERS')
        if transaction.transaction_type in ['transfer', 'genesis', 'reward']:
            self.accounts[transaction.sender][token] -= transaction.amount + transaction.fee
            self.accounts[transaction.recipient][token] += transaction.amount
        elif transaction.transaction_type == 'create_token':
            new_token = Token(
                name=transaction.data['name'],
                symbol=transaction.data['symbol'],
                total_supply=transaction.amount,
                creator=transaction.sender,
                is_minable=transaction.data.get('is_minable', False)
            )
            self.tokens[new_token.address] = new_token
            self.accounts[transaction.sender][new_token.address] = transaction.amount
        elif transaction.transaction_type == 'stake':
            self.accounts[transaction.sender]['BRAINERS'] -= transaction.amount + transaction.fee
            if transaction.sender not in self.validators:
                self.validators[transaction.sender] = Validator(transaction.sender, transaction.amount)
            else:
                self.validators[transaction.sender].stake += transaction.amount
        elif transaction.transaction_type == 'unstake':
            if transaction.sender in self.validators:
                self.validators[transaction.sender].stake -= transaction.amount
                self.accounts[transaction.sender]['BRAINERS'] += transaction.amount - transaction.fee
                if self.validators[transaction.sender].stake < self.min_stake:
                    self.validators[transaction.sender].is_active = False
        elif transaction.transaction_type == 'gift_validator':
            self.accounts[transaction.sender]['BRAINERS'] -= GIFT_VALIDATOR_BURN + transaction.fee
            self.validators[transaction.recipient] = Validator(transaction.recipient, GIFT_VALIDATOR_BURN, is_permanent=False)
        elif transaction.transaction_type == 'burn':
            self.accounts[transaction.sender][token] -= transaction.amount + transaction.fee
        elif transaction.transaction_type == 'execute_smart_contract':
            await self.execute_smart_contract(transaction)
        elif transaction.transaction_type == 'add_liquidity':
            await self.dex.add_liquidity(
                transaction.data['token_address'],
                transaction.amount,
                Fraction(transaction.data['token_amount']),
                transaction.sender,
                transaction.data['lock_time']
            )
        elif transaction.transaction_type == 'remove_liquidity':
            await self.dex.remove_liquidity(
                transaction.data['token_address'],
                transaction.amount,
                transaction.sender
            )
        elif transaction.transaction_type == 'place_order':
            await self.dex.place_order(
                transaction.data['token_address'],
                transaction.data['order_type'],
                transaction.amount,
                Fraction(transaction.data['price']),
                transaction.sender
            )

    async def execute_smart_contract(self, transaction: Transaction):
        contract = self.smart_contracts.get(transaction.recipient)
        if not contract:
            logger.error(f"Smart contract not found: {transaction.recipient}")
            return

        context = ExecutionContext(self, transaction.sender)
        try:
            result = await contract.execute(transaction.data['method'], transaction.data['params'], context)
            logger.info(f"Smart contract executed: {result}")
        except Exception as e:
            logger.error(f"Smart contract execution failed: {str(e)}")

    async def save_block(self, block: Block):
        await self.db_connection.execute(
            "INSERT OR REPLACE INTO blocks (hash, data) VALUES (?, ?)",
            (block.hash, json.dumps(block.to_dict(), cls=BrainersJSONEncoder))
        )
        for tx in block.transactions:
            await self.db_connection.execute(
                "INSERT OR REPLACE INTO transactions (hash, block_hash, data) VALUES (?, ?, ?)",
                (tx.hash, block.hash, json.dumps(tx.to_dict(), cls=BrainersJSONEncoder))
            )
        await self.db_connection.commit()

    async def get_block(self, block_hash: str) -> Optional[Block]:
        async with self.db_connection.execute("SELECT data FROM blocks WHERE hash = ?", (block_hash,)) as cursor:
            result = await cursor.fetchone()
            if result:
                return Block.from_dict(json.loads(result[0]))
        return None

    async def get_transaction(self, tx_hash: str) -> Optional[Transaction]:
        async with self.db_connection.execute("SELECT data FROM transactions WHERE hash = ?", (tx_hash,)) as cursor:
            result = await cursor.fetchone()
            if result:
                return Transaction.from_dict(json.loads(result[0]))
        return None

    def calculate_block_reward(self) -> Fraction:
        return Fraction(1, 1)

    async def get_balance(self, address: str, token: str = 'BRAINERS') -> Fraction:
        return self.accounts[address][token]

    async def get_token_info(self, token_address: str) -> Optional[Dict]:
        token = self.tokens.get(token_address)
        if token:
            return token.to_dict()
        return None

    async def get_validator_info(self, address: str) -> Optional[Dict]:
        validator = self.validators.get(address)
        if validator:
            return validator.to_dict()
        return None

    def calculate_state_root(self) -> str:
        state = {
            'accounts': self.accounts,
            'validators': self.validators,
            'tokens': self.tokens,
            'smart_contracts': self.smart_contracts
        }
        return hashlib.sha256(json.dumps(state, sort_keys=True, cls=BrainersJSONEncoder).encode()).hexdigest()

    async def sync_with_peer(self, peer_blocks: List[Dict]):
        for block_data in peer_blocks:
            block = Block.from_dict(block_data)
            if block.index > len(self.chain):
                if self.is_valid_block(block):
                    self.chain.append(block)
                    for tx in block.transactions:
                        await self.apply_transaction(tx)
                    await self.save_block(block)
                else:
                    logger.warning(f"Invalid block received: {block.hash}")

    def is_valid_block(self, block: Block) -> bool:
        if block.index > 0:
            previous_block = self.chain[block.index - 1]
            if block.previous_hash != previous_block.hash:
                return False
        for tx in block.transactions:
            if not self.verify_transaction(tx):
                return False
        return True

    async def reindex_blockchain(self):
        self.accounts = defaultdict(lambda: defaultdict(Fraction))
        self.validators = {}
        self.tokens = {}
        self.smart_contracts = {}

        for block in self.chain:
            for tx in block.transactions:
                await self.apply_transaction(tx)

        self.state_root = self.calculate_state_root()

    async def transfer_tokens(self, sender: str, recipient: str, amount: Fraction, token: str = 'BRAINERS') -> bool:
        transfer_tx = Transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            transaction_type="transfer",
            fee=self.calculate_transaction_fee(amount),
            data={'token': token}
        )
        return await self.add_transaction(transfer_tx)

    async def create_custom_token(self, creator: str, name: str, symbol: str, total_supply: Fraction, is_minable: bool, attributes: Dict[str, Any]) -> str:
        token_address = await self.create_token(creator, name, symbol, total_supply, is_minable)
        if token_address:
            self.tokens[token_address].attributes = attributes
        return token_address

    async def process_mempool(self):
        while self.mempool:
            new_block = await self.create_block()
            if new_block:
                logger.info(f"New block created: {new_block.hash}")
            else:
                break
        logger.info(f"Mempool processing complete. Remaining transactions: {len(self.mempool)}")

class BlockchainNode:
    def __init__(self, host: str, port: int, blockchain: Blockchain, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.peers = set()
        self.ssl_context = None
        self.use_ssl = use_ssl

    async def start(self):
        if self.use_ssl:
            try:
                self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                self.ssl_context.load_cert_chain('path/to/fullchain.pem', 'path/to/privkey.pem')
            except FileNotFoundError:
                logger.warning("SSL certificate files not found. Running without SSL.")
                self.use_ssl = False
        
        server = await websockets.serve(
            self.handle_connection, self.host, self.port, ssl=self.ssl_context if self.use_ssl else None
        )

        await self.blockchain.initialize_database()
        await self.blockchain.create_genesis_block()

        protocol = "wss" if self.use_ssl else "ws"
        logger.info(f"Node started on {protocol}://{self.host}:{self.port}")
        await server.wait_closed()

    async def handle_connection(self, websocket, path):
        peer = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        self.peers.add(peer)
        try:
            async for message in websocket:
                await self.process_message(websocket, message)
        finally:
            self.peers.remove(peer)

    async def process_message(self, websocket, message):
        data = json.loads(message)
        if data['type'] == 'new_transaction':
            tx = Transaction.from_dict(data['transaction'])
            success = await self.blockchain.add_transaction(tx)
            await websocket.send(json.dumps({'type': 'transaction_response', 'success': success}, cls=BrainersJSONEncoder))
        elif data['type'] == 'new_block':
            block = Block.from_dict(data['block'])
            if self.blockchain.is_valid_block(block):
                await self.blockchain.sync_with_peer([data['block']])
                await self.broadcast(message, exclude=websocket)
        elif data['type'] == 'get_blockchain_state':
            state = await self.blockchain.get_blockchain_state()
            await websocket.send(json.dumps({'type': 'blockchain_state', 'state': state}, cls=BrainersJSONEncoder))
        elif data['type'] == 'sync_request':
            last_block = data.get('last_block', -1)
            blocks_to_send = [block.to_dict() for block in self.blockchain.chain[last_block+1:]]
            await websocket.send(json.dumps({'type': 'sync_response', 'blocks': blocks_to_send}, cls=BrainersJSONEncoder))

    async def broadcast(self, message, exclude=None):
        for peer in self.peers:
            if peer != exclude:
                try:
                    async with websockets.connect(f'{"wss" if self.use_ssl else "ws"}://{peer}', ssl=self.ssl_context if self.use_ssl else None) as websocket:
                        await websocket.send(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast to {peer}: {str(e)}")

    async def process_transactions(self):
        await self.blockchain.process_mempool()

class BlockchainAPI:
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.app = web.Application()
        self.setup_routes()

    def setup_routes(self):
        self.app.router.add_get('/balance/{address}', self.get_balance)
        self.app.router.add_get('/transaction/{tx_hash}', self.get_transaction)
        self.app.router.add_get('/block/{block_hash}', self.get_block)
        self.app.router.add_post('/transaction', self.create_transaction)
        self.app.router.add_get('/token/{token_address}', self.get_token_info)
        self.app.router.add_get('/validator/{address}', self.get_validator_info)
        self.app.router.add_get('/state', self.get_blockchain_state)
        self.app.router.add_post('/stake', self.stake_tokens)
        self.app.router.add_post('/unstake', self.unstake_tokens)
        self.app.router.add_post('/burn', self.burn_tokens)
        self.app.router.add_post('/create_token', self.create_token)
        self.app.router.add_post('/create_smart_contract', self.create_smart_contract)
        self.app.router.add_post('/execute_smart_contract', self.execute_smart_contract)
        self.app.router.add_get('/transaction_history/{address}', self.get_transaction_history)

    async def get_balance(self, request):
        address = request.match_info['address']
        token = request.query.get('token', 'BRAINERS')
        balance = await self.blockchain.get_balance(address, token)
        return web.json_response({'balance': str(balance)})

    async def get_transaction(self, request):
        tx_hash = request.match_info['tx_hash']
        tx = await self.blockchain.get_transaction(tx_hash)
        if tx:
            return web.json_response(tx.to_dict())
        return web.json_response({'error': 'Transaction not found'}, status=404)

    async def get_block(self, request):
        block_hash = request.match_info['block_hash']
        block = await self.blockchain.get_block(block_hash)
        if block:
            return web.json_response(block.to_dict())
        return web.json_response({'error': 'Block not found'}, status=404)

    async def create_transaction(self, request):
        data = await request.json()
        tx = Transaction(
            sender=data['sender'],
            recipient=data['recipient'],
            amount=Fraction(data['amount']),
            transaction_type=data['type'],
            fee=self.blockchain.calculate_transaction_fee(Fraction(data['amount'])),
            data=data.get('data', {})
        )
        success = await self.blockchain.add_transaction(tx)
        return web.json_response({'success': success})

    async def get_token_info(self, request):
        token_address = request.match_info['token_address']
        token_info = await self.blockchain.get_token_info(token_address)
        if token_info:
            return web.json_response(token_info)
        return web.json_response({'error': 'Token not found'}, status=404)

    async def get_validator_info(self, request):
        address = request.match_info['address']
        validator_info = await self.blockchain.get_validator_info(address)
        if validator_info:
            return web.json_response(validator_info)
        return web.json_response({'error': 'Validator not found'}, status=404)

    async def get_blockchain_state(self, request):
        state = await self.blockchain.get_blockchain_state()
        return web.json_response(state)

    async def stake_tokens(self, request):
        data = await request.json()
        success = await self.blockchain.stake_tokens(data['staker'], Fraction(data['amount']))
        return web.json_response({'success': success})

    async def unstake_tokens(self, request):
        data = await request.json()
        success = await self.blockchain.unstake_tokens(data['staker'], Fraction(data['amount']))
        return web.json_response({'success': success})

    async def burn_tokens(self, request):
        data = await request.json()
        success = await self.blockchain.burn_tokens(data['burner'], Fraction(data['amount']), data.get('token', 'BRAINERS'))
        return web.json_response({'success': success})

    async def create_token(self, request):
        data = await request.json()
        token_address = await self.blockchain.create_token(
            data['creator'],
            data['name'],
            data['symbol'],
            Fraction(data['total_supply']),
            data.get('is_minable', False)
        )
        return web.json_response({'token_address': token_address})

    async def create_smart_contract(self, request):
        data = await request.json()
        contract_address = await self.blockchain.create_smart_contract(
            data['creator'],
            data['code'],
            data['abi']
        )
        return web.json_response({'contract_address': contract_address})

    async def execute_smart_contract(self, request):
        data = await request.json()
        result = await self.blockchain.execute_smart_contract(
            Transaction(
                sender=data['sender'],
                recipient=data['contract_address'],
                amount=Fraction(0),
                transaction_type='execute_smart_contract',
                fee=self.blockchain.calculate_transaction_fee(Fraction(0)),
                data={
                    'method': data['method'],
                    'params': data['params']
                }
            )
        )
        return web.json_response({'result': result})

    async def get_transaction_history(self, request):
        address = request.match_info['address']
        history = await self.blockchain.get_transaction_history(address)
        return web.json_response(history)

async def main():
    if len(sys.argv) < 3:
        print("Usage: python brainers_blockchain.py <host> <port> [use_ssl]")
        return

    host = sys.argv[1]
    port = int(sys.argv[2])
    use_ssl = len(sys.argv) > 3 and sys.argv[3].lower() == 'true'
    
    blockchain = Blockchain(INITIAL_BRAINERS_SUPPLY)
    node = BlockchainNode(host, port, blockchain, use_ssl)
    api = BlockchainAPI(blockchain)
    
    runner = web.AppRunner(api.app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    
    await asyncio.gather(
        node.start(),
        site.start()
    )

    try:
        while True:
            await asyncio.sleep(1)
            await node.process_transactions()
    except KeyboardInterrupt:
        print("Shutting down the blockchain node...")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
