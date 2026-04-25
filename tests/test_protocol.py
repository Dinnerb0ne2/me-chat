import io
import unittest

from me_chat.protocol import Frame, ProtocolError, parse_json_line, read_line_limited


class ProtocolTests(unittest.TestCase):
    def test_frame_roundtrip(self):
        line = Frame("chat", {"a": 1}).to_json_line()
        frame = parse_json_line(line[:-1])
        self.assertEqual(frame.kind, "chat")
        self.assertEqual(frame.payload["a"], 1)

    def test_invalid_json_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_json_line(b"not-json")

    def test_read_line_limited(self):
        reader = io.BytesIO(b'{"type":"ping"}\n')
        line = read_line_limited(reader)
        self.assertEqual(line, b'{"type":"ping"}')


if __name__ == "__main__":
    unittest.main()
