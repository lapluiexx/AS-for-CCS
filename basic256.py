import time
import hashlib
from ecdsa import SECP256k1, SigningKey, BadSignatureError
from ecdsa.util import sigencode_der, sigdecode_der

# --- Basic ECDSA Implementation ---
class BasicECDSA:
    def __init__(self):
        # 标准 ECDSA
        self.curve = SECP256k1
        self.order = SECP256k1.order
        self.hash_func = hashlib.sha256

    # [1] KeyGen
    def key_gen(self):
        """
        Standard KeyGen: Generates a random private key and corresponding public key.
        """
        sk = SigningKey.generate(curve=self.curve, hashfunc=self.hash_func)
        return sk, sk.get_verifying_key()

    # [2] Sign
    def sign(self, sk, m):
        """
        Standard ECDSA Sign: Uses a random nonce 'k' (system entropy).
        """
        # ecdsa 库默认会生成随机 k
        sig = sk.sign(m, sigencode=sigencode_der)
        # 解码为 (r, s) 元组以便于查看或存储
        return sigdecode_der(sig, self.order)

    # [3] Verify
    def verify(self, pk, m, sigma):
        """
        Standard ECDSA Verify.
        """
        r, s = sigma
        sig_der = sigencode_der(r, s, self.order)
        try:
            return pk.verify(sig_der, m)
        except BadSignatureError:
            return False


# --- Main Execution with Timing ---
if __name__ == "__main__":
    scheme = BasicECDSA()
    print(f"{'Algorithm':<15} | {'Time (ms)':<15}")
    print("-" * 35)

    # 准备工作
    msg = b"Test Message for Basic ECDSA"

    # 1. KeyGen
    start = time.perf_counter()
    sk, pk = scheme.key_gen()
    end = time.perf_counter()
    print(f"{'KeyGen':<15} | {(end - start) * 1000:.4f} ms")

    # 2. Sign
    start = time.perf_counter()
    sigma = scheme.sign(sk, msg)
    end = time.perf_counter()
    print(f"{'Sign':<15} | {(end - start) * 1000:.4f} ms")

    # 3. Verify
    start = time.perf_counter()
    valid = scheme.verify(pk, msg, sigma)
    end = time.perf_counter()
    print(f"{'Verify':<15} | {(end - start) * 1000:.4f} ms")