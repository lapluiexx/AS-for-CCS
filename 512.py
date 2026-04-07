import time
import hashlib
import os
from ecdsa import NIST521p, SigningKey, BadSignatureError
from ecdsa.util import sigencode_der, sigdecode_der


# --- AS-ECDSA Implementation (P-521 + Figure 3 Logic) ---
class AS_ECDSA_521:
    def __init__(self):

        self.curve = NIST521p
        self.order = NIST521p.order
        self.generator = NIST521p.generator

        self.hash_func = hashlib.sha512
        self.zkp = Groth16Simulator()

    def _circuit(self, stmt, wit):
        """
        ZKP Circuit for P-521:
        Verifies:
        1. pk derived from seed via SHA-512 KDF
        2. signature constructed using nonce c = (k + seed) mod q
        """
        pk_bytes, m, (r, s) = stmt
        seed, k = wit

        # [Logic 1] Re-derive SK (Using SHA-512)
        sk_int = int.from_bytes(self.hash_func(b"AS-KDF-P521:" + seed).digest(), 'big') % self.order
        sk_obj = SigningKey.from_secret_exponent(sk_int, curve=self.curve, hashfunc=self.hash_func)

        if sk_obj.get_verifying_key().to_string() != pk_bytes:
            return False

        # [Logic 2] Verify Nonce Construction c = k + seed
        seed_int = int.from_bytes(seed, 'big')
        c = (k + seed_int) % self.order

        # Verify s calculation
        z = int.from_bytes(self.hash_func(m).digest(), 'big')
        try:
            c_inv = pow(c, -1, self.order)
            s_expected = (c_inv * (z + r * sk_int)) % self.order
            return s == s_expected
        except Exception:
            return False

    def seed_gen(self):
        # [Change] P-521 建议使用 64 字节 (512 bits) 种子
        return os.urandom(64)

    # [1] AS.Setup
    def setup(self):
        pk, vk = self.zkp.setup(self._circuit)
        return {"pk": pk, "vk": vk}

    # [2] AS.KeyGen
    def key_gen(self, seed, pp):
        # KDF using SHA-512
        sk_int = int.from_bytes(self.hash_func(b"AS-KDF-P521:" + seed).digest(), 'big') % self.order
        sk = SigningKey.from_secret_exponent(sk_int, curve=self.curve, hashfunc=self.hash_func)
        return sk, sk.get_verifying_key()

    # [3] AS.Sign (Standard)
    def sign(self, pp, sk, m):

        sig = sk.sign(m, hashfunc=self.hash_func, sigencode=sigencode_der)
        return sigdecode_der(sig, self.order)

    # [4] AS.SignAuth (Strictly following Figure 3 for P-521)
    def sign_auth(self, pp, seed, m):
        # Step 7 (Pre-computation): sk = KDF(seed)
        sk_int = int.from_bytes(self.hash_func(b"AS-KDF-P521:" + seed).digest(), 'big') % self.order
        sk_obj = SigningKey.from_secret_exponent(sk_int, curve=self.curve, hashfunc=self.hash_func)

        # Step 2: z = H(m)
        z = int.from_bytes(self.hash_func(m).digest(), 'big')

        # Step 3: Select random k (64 bytes for P-521)
        k = int.from_bytes(os.urandom(64), 'big') % self.order

        # Step 4: c = (k + seed) mod q
        seed_int = int.from_bytes(seed, 'big')
        c = (k + seed_int) % self.order

        # Step 5: R = c * G
        R = c * self.generator

        # Step 6: r = R.x mod q
        r = R.x() % self.order

        # Step 8: s = c^{-1}(z + r * sk) mod q
        c_inv = pow(c, -1, self.order)
        s = (c_inv * (z + r * sk_int)) % self.order

        sigma = (r, s)

        # Step 10-12: Generate Proof
        pk_bytes = sk_obj.get_verifying_key().to_string()
        stmt = (pk_bytes, m, sigma)
        wit = (seed, k)

        pi = self.zkp.prove(pp['pk'], stmt, wit)

        return (sigma, pi)

    # [5] AS.Verify
    def verify(self, pp, pk, m, sigma):
        r, s = sigma
        sig_der = sigencode_der(r, s, self.order)
        try:
            return pk.verify(sig_der, m, hashfunc=self.hash_func)
        except BadSignatureError:
            return False

    # [6] AS.VerAuth
    def ver_auth(self, pp, pk, m, auth):
        sigma, pi = auth
        if not self.verify(pp, pk, m, sigma):
            return False

        pk_bytes = pk.to_string()
        return self.zkp.verify(pp['vk'], (pk_bytes, m, sigma), pi)


# --- Main Execution with Timing ---
if __name__ == "__main__":
    scheme = AS_ECDSA_521()
    print(f"{'Algorithm (P-521)':<20} | {'Time (ms)':<15}")
    print("-" * 40)

    msg = b"P-521 Top Secret Message"
    seed = scheme.seed_gen()

    # 1. AS.Setup
    start = time.perf_counter()
    pp = scheme.setup()
    end = time.perf_counter()
    print(f"{'AS.Setup':<20} | {(end - start) * 1000:.4f} ms")

    # 2. AS.KeyGen
    start = time.perf_counter()
    sk, pk = scheme.key_gen(seed, pp)
    end = time.perf_counter()
    print(f"{'AS.KeyGen':<20} | {(end - start) * 1000:.4f} ms")

    # 3. AS.Sign
    start = time.perf_counter()
    sigma = scheme.sign(pp, sk, msg)
    end = time.perf_counter()
    print(f"{'AS.Sign':<20} | {(end - start) * 1000:.4f} ms")

    # 4. AS.SignAuth
    start = time.perf_counter()
    auth_tuple = scheme.sign_auth(pp, seed, msg)
    end = time.perf_counter()
    print(f"{'AS.SignAuth':<20} | {(end - start) * 1000:.4f} ms")

    # 5. AS.Verify
    start = time.perf_counter()
    valid = scheme.verify(pp, pk, msg, sigma)
    end = time.perf_counter()
    print(f"{'AS.Verify':<20} | {(end - start) * 1000:.4f} ms")

    # 6. AS.VerAuth
    start = time.perf_counter()
    valid_auth = scheme.ver_auth(pp, pk, msg, auth_tuple)
    end = time.perf_counter()
    print(f"{'AS.VerAuth':<20} | {(end - start) * 1000:.4f} ms")