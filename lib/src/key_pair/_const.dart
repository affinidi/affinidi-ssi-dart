import 'dart:typed_data';

var STATIC_HKD_NONCE = Uint8List(12); // Use a nonce (e.g., 12-byte for AES-GCM)
var FULL_PUB_KEY_LENGTH = 64;
var COMPRESSED_PUB_KEY_LENGTH = 32;