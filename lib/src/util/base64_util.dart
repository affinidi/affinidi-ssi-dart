import 'dart:convert';
import 'dart:typed_data';

/// Encode [input] as base64 URL encoding without adding padding
String base64UrlNoPadEncode(Uint8List input) {
  final b64Padded = base64UrlEncode(input);

  var lastNoPadIndex = b64Padded.length - 1;
  while (lastNoPadIndex > 0 && b64Padded[lastNoPadIndex] == '=') {
    lastNoPadIndex--;
  }

  return b64Padded.substring(0, lastNoPadIndex + 1);
}

/// Decode [input] from base64 URL encoding without padding
Uint8List base64UrlNoPadDecode(String input) {
  var pad = (4 - (input.length & 3)) & 3;

  return base64Url.decode(
    input.padRight(input.length + pad, '='),
  );
}

// String addPaddingToBase64(String base64Input) {
//   while (base64Input.length % 4 != 0) {
//     base64Input += '=';
//   }
//   return base64Input;
// }
//
// String removePaddingFromBase64(String base64Input) {
//   while (base64Input.endsWith('=')) {
//     base64Input = base64Input.substring(0, base64Input.length - 1);
//   }
//   return base64Input;
// }
