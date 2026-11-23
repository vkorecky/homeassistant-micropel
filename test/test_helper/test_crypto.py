"""Test of cryptography."""
from ...helper.crypto import Crypto


def test_encrypt_decrypt_test():
    """Test encoding and decoding."""

    original_str = "Sww=BRDqXPgX5ytH"
    exp_str_pass1 = "Ffz7WCI{MAjR hyB"
    exp_str_pass999999 = 'Mgf"\\BUnF@vG+ieW'

    cryptography = Crypto()

    cryptography.crypt_init(1)
    encoded_str = cryptography.code_string(original_str)
    assert exp_str_pass1 == encoded_str
    decoded_str = cryptography.decode_string(encoded_str)
    assert original_str == decoded_str

    cryptography.crypt_init(999999)
    encoded_str = cryptography.code_string(original_str)
    assert exp_str_pass999999 == encoded_str
    decoded_str = cryptography.decode_string(encoded_str)
    assert original_str == decoded_str

    cryptography.crypt_init(0)
    encoded_str = cryptography.code_string(original_str)
    assert original_str == encoded_str
    decoded_str = cryptography.decode_string(encoded_str)
    assert original_str == decoded_str

    cryptography.crypt_init(-1)
    encoded_str = cryptography.code_string(original_str)
    assert original_str == encoded_str
    decoded_str = cryptography.decode_string(encoded_str)
    assert original_str == decoded_str


def test_crypt_out_reset():
    """The reset of the outgoing counter makes the next frame start with the first key byte."""
    cryptography = Crypto()
    cryptography.crypt_init(468945)
    first = cryptography.decode_string("19.!><&28J")
    cryptography.decode_string("123")  # the counter is now in the middle of a frame
    cryptography.crypt_out_reset()
    assert cryptography.decode_string("19.!><&28J") == first


def test_crypt_init_without_password():
    """No password means no encryption."""
    cryptography = Crypto()
    cryptography.crypt_init(None)
    assert cryptography.code_string("@01*2E") == "@01*2E"
