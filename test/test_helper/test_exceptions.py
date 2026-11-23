"""Tests of exceptions."""
from ...helper.exceptions import CommandError, InvalidCrcError, InvalidMessageError


def test_invalid_crc_error():
    """The message contains both CRCs."""
    error = InvalidCrcError("55", "56")
    assert error.expected_crc == "55"
    assert error.message_crc == "56"
    assert "'55'" in str(error)
    assert "'56'" in str(error)


def test_invalid_message_error():
    """The message contains the received message."""
    error = InvalidMessageError("*03")
    assert error.received_message == "*03"
    assert "'*03'" in str(error)


def test_command_error():
    """The message contains the received message."""
    error = CommandError("!03")
    assert error.received_message == "!03"
    assert "'!03'" in str(error)
