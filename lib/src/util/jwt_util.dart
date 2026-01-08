import 'dart:convert';

import '../did/did_signer.dart';
import 'base64_util.dart';

/// Utility class for handling JWT operations.
class JwtUtil {
  final DidSigner _signer;

  /// Creates a JwtUtil instance with the given [signer].
  JwtUtil(DidSigner signer) : _signer = signer;

  /// Signs a JWT with the given [header] and [payload].
  Future<Map<String, String>> signJwt(
      Map<String, dynamic> header, Map<String, dynamic> payload) async {
    final encodedHeader = base64UrlNoPadEncode(
      utf8.encode(jsonEncode(header)),
    );
    final encodedPayload = base64UrlNoPadEncode(
      utf8.encode(jsonEncode(payload)),
    );
    final toSign = ascii.encode('$encodedHeader.$encodedPayload');
    final signature = base64UrlNoPadEncode(
      await _signer.sign(toSign),
    );

    final serialized = '$encodedHeader.$encodedPayload.$signature';
    return {
      'signature': signature,
      'serialized': serialized,
    };
  }
}
