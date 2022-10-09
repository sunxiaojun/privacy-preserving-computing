import sys
import random

import pytest

sys.path.append("..")
from paillier_crt import Paillier, PaillierKeyGenerator, CryptoNumber


class Test:
    @pytest.fixture()
    def set_up(self):
        print('start paillier crt tests')
        key_size = 2048
        public_key, private_key = PaillierKeyGenerator.generate_keypair(key_size)
        self.encrypt_cipher = Paillier(Paillier.CIPHER_MODE_ENCRYPT, public_key)
        self.decrypt_cipher = Paillier(Paillier.CIPHER_MODE_DECRYPT, private_key)

        yield

        print('finish paillier crt tests')

    def test_encrypt(self, set_up):
        for _ in range(10):
            m = random.randint(10000, 2 << 31 - 1)
            cipher_text = self.encrypt_cipher.encrypt(m)
            plain_text = self.decrypt_cipher.decrypt(cipher_text)

            assert m == plain_text, f'wrong decryption text'

    def test_homomorphic_add(self, set_up):
        for _ in range(10):
            m1 = random.randint(10000, 2 << 31 - 1)
            cipher_text1 = self.encrypt_cipher.encrypt(m1)

            m2 = random.randint(10000, 2 << 31 - 1)
            cipher_text2 = self.encrypt_cipher.encrypt(m2)
            cipher_text = cipher_text1 + cipher_text2
            plain_text = self.decrypt_cipher.decrypt(cipher_text)

            assert m1 + m2 == plain_text, f'wrong homomorphic add result'

    def test_homomorphic_mul(self, set_up):
        for _ in range(10):
            m1 = random.randint(10000, 2 << 31 - 1)
            cipher_text1 = self.encrypt_cipher.encrypt(m1)

            k = random.randint(1, 10000)
            cipher_text = cipher_text1 * k
            plain_text = self.decrypt_cipher.decrypt(cipher_text)

            assert m1 * k == plain_text, f'wrong homomorphic mul result'


if __name__ == '__main__':
    pytest.main(['-s', '-rp', 'test_paillier_crt.py'])
