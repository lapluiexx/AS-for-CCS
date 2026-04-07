import time
import hashlib
from ecdsa import NIST521p, SigningKey, BadSignatureError
from ecdsa.util import sigencode_der, sigdecode_der


# --- Basic ECDSA Implementation (P-521) ---
class BasicECDSA521:
    def __init__(self):

        self.curve = NIST521p
        self.order = NIST521p.order

        self.hash_func = hashlib.sha512

    # [1] KeyGen
    def key_gen(self):
        """
        Standard KeyGen: Generates a random private key on P-521.
        """
        sk = SigningKey.generate(curve=self.curve, hashfunc=self.hash_func)
        return sk, sk.get_verifying_key()

    # [2] Sign
    def sign(self, sk, m):
        """
        Standard ECDSA Sign: Uses random nonce 'k'.
        """
        sig = sk.sign(m, sigencode=sigencode_der)
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
    scheme = BasicECDSA521()
    print(f"{'Algorithm (P-521)':<20} | {'Time (ms)':<15}")
    print("-" * 40)

    # 准备工作
    msg = b"Test Message for Basic ECDSA P-521"

    # 1. KeyGen
    start = time.perf_counter()
    sk, pk = scheme.key_gen()
    end = time.perf_counter()
    print(f"{'KeyGen':<20} | {(end - start) * 1000:.4f} ms")

    # 2. Sign
    start = time.perf_counter()
    sigma = scheme.sign(sk, msg)
    end = time.perf_counter()
    print(f"{'Sign':<20} | {(end - start) * 1000:.4f} ms")

    # 3. Verify
    start = time.perf_counter()
    valid = scheme.verify(pk, msg, sigma)
    end = time.perf_counter()
    print(f"{'Verify':<20} | {(end - start) * 1000:.4f} ms")

    # 有效性检查
    print("-" * 40)
    print(f"Signature Valid? {valid}")
    # P-521 的签名非常长 (r, s 各约 66 字节)
    print(f"Signature Size (r, s): {len(str(sigma))} chars (approx representation)")