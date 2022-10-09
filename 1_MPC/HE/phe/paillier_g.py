import random
from collections import namedtuple

import gmpy2

"""优化原版Paillier算法的参数g"""
"""Optimize paillier algorithm's g parameter"""


class PaillierKeyGenerator:

    @staticmethod
    def _get_prime_over(N):
        rand_func = random.SystemRandom()
        r = gmpy2.mpz(rand_func.getrandbits(N))
        r = gmpy2.bit_set(r, N - 1)
        return int(gmpy2.next_prime(r))

    @staticmethod
    def _generate_p_q(key_size):
        p = q = None
        n_len = 0
        while n_len != key_size:
            p = PaillierKeyGenerator._get_prime_over(key_size // 2)
            q = p
            while q == p:
                q = PaillierKeyGenerator._get_prime_over(key_size // 2)
            n = p * q
            n_len = n.bit_length()
        return p, q

    @staticmethod
    def generate_keypair(key_size):
        p, q = PaillierKeyGenerator._generate_p_q(key_size)

        n = p * q
        lam = gmpy2.lcm(p - 1, q - 1)
        g = n + 1
        mu = gmpy2.invert(lam, n)

        PublicKey = namedtuple("PublicKey", "n g")
        PrivateKey = namedtuple("PrivateKey", "public_key lam mu")
        public_key = PublicKey(n=n, g=g)
        private_key = PrivateKey(public_key=public_key, lam=lam, mu=mu)
        return public_key, private_key


class Paillier:
    CIPHER_MODE_ENCRYPT = 0
    CIPHER_MODE_DECRYPT = 1

    def __init__(self, cipher_mode, cipher_key):
        if cipher_mode == Paillier.CIPHER_MODE_ENCRYPT:
            self.public_key = cipher_key
            self.private_key = None
        elif cipher_mode == Paillier.CIPHER_MODE_DECRYPT:
            self.public_key = cipher_key.public_key
            self.private_key = cipher_key
        else:
            raise ValueError('cipher_mode value must be either CIPHER_MODE_ENCRYPT or CIPHER_MODE_DECRYPT')
        self.cipher_mode = cipher_mode
        self.n_square = pow(self.public_key.n, 2)

    def fn_L(self, x):
        return (x - 1) // self.public_key.n

    def encrypt(self, m):
        r = random.randint(1, self.public_key.n - 1)
        # 使用powmod优化模幂运算
        cipher_text = gmpy2.mod((self.public_key.n * m + 1) * gmpy2.powmod(r, self.public_key.n, self.n_square),
                                self.n_square)
        return CryptoNumber(cipher_text, self.n_square)

    def decrypt(self, crypto_number):
        # 使用powmod优化模幂运算
        numerator = self.fn_L(gmpy2.powmod(crypto_number.cipher_text, self.private_key.lam, self.n_square))
        return gmpy2.mod(numerator * self.private_key.mu, self.public_key.n)


class CryptoNumber:
    def __init__(self, cipher_text, n_square):
        self.cipher_text = cipher_text
        self.n_square = n_square

    def __add__(self, other):
        if isinstance(other, CryptoNumber):
            sum_ciphertext = gmpy2.mod(self.cipher_text * other.cipher_text, self.n_square)
            return CryptoNumber(sum_ciphertext, self.n_square)
        else:
            pass

    def __mul__(self, other):
        if isinstance(other, CryptoNumber):
            raise NotImplementedError('not supported between instance of "CryptoNumber" and "CryptoNumber"')
        else:
            mul_cipher_text = gmpy2.mod(pow(self.cipher_text, other), self.n_square)
            return CryptoNumber(mul_cipher_text, self.n_square)
