import 'dart:convert';

import '../did/did_signer.dart';
import 'base64_util.dart';

/// Result of JWT signing operation.
class JwtSignResult {
  /// The signature component of the JWT.
  final String signature;

  /// The complete serialized JWT string.
  final String serialized;

  /// Creates a [JwtSignResult] instance.
  JwtSignResult({
    required this.signature,
    required this.serialized,
  });
}

/// Utility class for handling JWT operations.
class JwtUtil {
  final DidSigner _signer;

  /// Creates a JwtUtil instance with the given [signer].
  JwtUtil(DidSigner signer) : _signer = signer;

  /// Signs a JWT with the given [header] and [payload].
  Future<JwtSignResult> signJwt(
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
    return JwtSignResult(signature: signature, serialized: serialized);
  }
}
