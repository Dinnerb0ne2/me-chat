import unittest

from me_chat.crypto import (
    CryptoError,
    derive_room_key,
    derive_user_password_hash,
    open_sealed,
    seal,
    verify_user_password,
)


class CryptoTests(unittest.TestCase):
    def test_seal_open_roundtrip(self):
        key = derive_room_key("passphrase", "room-a")
        sealed = seal(key, "hello")
        pt = open_sealed(key, sealed).decode("utf-8")
        self.assertEqual(pt, "hello")

    def test_tamper_detected(self):
        key = derive_room_key("passphrase", "room-a")
        sealed = seal(key, "hello", b"aad")
        tampered = sealed.__class__(
            nonce_b64=sealed.nonce_b64,
            ciphertext_b64=sealed.ciphertext_b64,
            mac_b64=sealed.mac_b64[:-2] + "AA",
        )
        with self.assertRaises(CryptoError):
            open_sealed(key, tampered, b"aad")

    def test_verify_user_password_rejects_invalid_base64(self):
        self.assertFalse(verify_user_password("pw", "not-base64", "not-base64"))

    def test_verify_user_password_roundtrip(self):
        salt, digest = derive_user_password_hash("pw")
        self.assertTrue(verify_user_password("pw", salt, digest))
        self.assertFalse(verify_user_password("wrong", salt, digest))


if __name__ == "__main__":
    unittest.main()
