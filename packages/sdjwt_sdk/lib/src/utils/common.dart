import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Generates a base64 encoded, URL formatted and 128 bits long random salt.
///
/// This function creates a cryptographically secure random salt that can be
/// used in the SD-JWT disclosure process.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Returns a base64url-encoded random salt string.
String generateSecureSalt() {
  final random = Random.secure();
  final bytes = Uint8List(16); // 128 bits long
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return base64UrlEncode(bytes);
}

/// Returns the current timestamp in seconds.
///
/// This function is used for generating JWT timestamps like iat, exp, and nbf.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Returns the current Unix timestamp in seconds.
int jwtNow() {
  return DateTime.now().millisecondsSinceEpoch ~/ 1000;
}

/// Converts the given input to a Base64Url encoded string.
///
/// Parameters:
/// - **[input]**: The input to be encoded. This could be bytes or any other object type that can be json encoded.
///
/// Returns the base64Url encoded string.
String base64UrlEncode(dynamic input) {
  if (input is List<int> || input is Uint8List) {
    return toBase64EncodedBytes(input);
  }
  return toBase64EncodedBytes(utf8.encode(json.encode(input)));
}

/// Converts the given bytes to a Base64Url encoded string.
///
/// Parameters:
/// - **[input]**: The input bytes to be encoded.
///
/// Returns the base64Url encoded string.
String toBase64EncodedBytes(List<int> input) {
  return base64Url.encode(input).replaceAll('=', '');
}

/// Returns json object from bytes
///
/// Parameters:
/// - **[input]**: The input bytes to be decoded.
///
/// Returns the json object.
Map<String, dynamic> fromEncodedBytes(List<int> input) {
  return json.decode(utf8.decode(input));
}

/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
extension MapExtension on Map<String, dynamic> {
  /// Converts this map to a JSON-compatible map by encoding and then decoding it.
  ///
  /// This process ensures that all values in the map are JSON-compatible.
  ///
  /// Returns a new map with JSON-compatible values.
  Map<String, Object?> clone() {
    return json.decode(json.encode(this));
  }
}
