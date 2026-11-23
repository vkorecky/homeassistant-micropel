"""Tests of building and parsing messages for PLCs."""
import pytest

from ...helper.exceptions import InvalidMessageError
from ...helper.message import Message


def test_build_message():
    """Test of message building."""
    expected_message = "*160220#55"
    message = Message.build_message(None, "*", 0x16, "0220")
    assert message == expected_message

    expected_message = "*0361646D696E64617400#5E"
    message = Message.build_message(None, "*", 0x03, "61646D696E64617400")
    assert message == expected_message

    expected_message = "*16022012345678#F9"
    message = Message.build_message(None, "*", 0x16, "022012345678")
    assert message == expected_message

    expected_message = "@01*16022012345678#9A"
    message = Message.build_message(1, "*", 0x16, "022012345678")
    assert message == expected_message

    expected_message = "*03#8D"
    message = Message.build_message(None, "*", 0x03, None)
    assert message == expected_message


def test_get_crc():
    """Test of CRC."""
    expected_result = "55"
    result = Message.get_crc("*160220#55")
    assert result == expected_result

    expected_result = "5E"
    result = Message.get_crc("*0361646D696E64617400#5E")
    assert result == expected_result

    expected_result = "F9"
    result = Message.get_crc("*16022012345678#F9")
    assert result == expected_result

    expected_result = "9A"
    result = Message.get_crc("@01*16022012345678#9A")
    assert result == expected_result

    expected_result = "8D"
    result = Message.get_crc("*03#8D")
    assert result == expected_result


def test_get_plc_address():
    """Test of PLC address parsing."""
    expected_result = None
    result = Message.get_plc_address("*160220#55")
    assert result == expected_result

    expected_result = "01"
    result = Message.get_plc_address("@01*16022012345678#9A")
    assert result == expected_result


def test_get_cmd_id():
    """Test of parsing CMD ID."""
    expected_result = "16"
    result = Message.get_cmd_id("*160220#55")
    assert result == expected_result

    expected_result = "03"
    result = Message.get_cmd_id("*0361646D696E64617400#5E")
    assert result == expected_result

    expected_result = "16"
    result = Message.get_cmd_id("!16022035#84")
    assert result == expected_result

    expected_result = "16"
    result = Message.get_cmd_id("@01*16022012345678#9A")
    assert result == expected_result

    expected_result = "16"
    result = Message.get_cmd_id("@01!16022035#84")
    assert result == expected_result

    expected_result = "03"
    result = Message.get_cmd_id("*03#8D")
    assert result == expected_result


def test_get_cmd_type():
    """Test of parsing CMD type."""
    expected_result = "*"
    result = Message.get_cmd_type("*160220#55")
    assert result == expected_result

    expected_result = "*"
    result = Message.get_cmd_type("*0361646D696E64617400#5E")
    assert result == expected_result

    expected_result = "!"
    result = Message.get_cmd_type("!16022035#84")
    assert result == expected_result

    expected_result = "*"
    result = Message.get_cmd_type("@01*16022012345678#9A")
    assert result == expected_result

    expected_result = "!"
    result = Message.get_cmd_type("@01!16022035#84")
    assert result == expected_result

    expected_result = "*"
    result = Message.get_cmd_type("*03#8D")
    assert result == expected_result


def test_get_data():
    """Test of parsing data from message."""
    expected_result = "0220"
    result = Message.get_data("*160220#55")
    assert result == expected_result

    expected_result = "61646D696E64617400"
    result = Message.get_data("*0361646D696E64617400#5E")
    assert result == expected_result

    expected_result = "022012345678"
    result = Message.get_data("*16022012345678#F9")
    assert result == expected_result

    expected_result = "022012345678"
    result = Message.get_data("@01*16022012345678#9A")
    assert result == expected_result

    expected_result = "022035"
    result = Message.get_data("!16022035#84")
    assert result == expected_result

    expected_result = "022035"
    result = Message.get_data("@02!16022035#84")
    assert result == expected_result

    expected_result = None
    result = Message.get_data("*03#8D")
    assert result == expected_result


def test_is_valid_message():
    """Only messages of at least 6 characters are considered usable."""
    assert Message.is_valid_message(None) is True
    assert Message.is_valid_message("*03#8D") is False
    assert Message.is_valid_message("*03") is True


def test_message_without_command_marker():
    """A message decoded with a wrong password has no '*' or '!'."""
    assert Message.get_cmd_id("garbage-no-marker") is None
    with pytest.raises(InvalidMessageError):
        Message.get_cmd_type("garbage-no-marker")
    with pytest.raises(InvalidMessageError):
        Message.get_data("garbage-no-marker")


def test_message_without_crc_has_no_data():
    """Without the '#' the data cannot be found."""
    with pytest.raises(InvalidMessageError):
        Message.get_data("@01*2E000000D0")


@pytest.mark.parametrize(
    "method",
    [
        Message.get_crc,
        Message.get_plc_address,
        Message.get_cmd_id,
        Message.get_data,
        Message.get_cmd_type,
    ],
)
def test_too_short_message_is_invalid(method):
    """Every parser refuses a message which is too short."""
    with pytest.raises(InvalidMessageError):
        method("*03")
