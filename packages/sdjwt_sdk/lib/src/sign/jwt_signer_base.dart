import 'dart:convert';

import 'package:sdjwt_sdk/src/sign/signer.dart';
import 'package:sdjwt_sdk/src/utils/common.dart';

/// A mixin that provides common JWT signing functionality.
///
/// This mixin includes methods for generating signed compact jwt.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
mixin JwtSigner {
  /// Generates a signed compact JWT from the [claims] as payload and [protectedHeaders]
  /// as header using the provided [signer].
  ///
  /// Parameters:
  /// - **[signer]**: The signer for signing the JWT.
  /// - **[claims]**: The claims to be included in the JWT payload.
  /// - **[protectedHeaders]**: The headers to include in the signed JWT.
  ///
  /// Returns a compact serialized JWT string.
  String generateSignedCompactJwt({
    required Signer signer,
    required Map<String, dynamic> claims,
    Map<String, dynamic> protectedHeaders = const {},
  }) {
    final headers = <String, dynamic>{'alg': signer.algIanaName};

    if (signer.keyId != null) {
      headers['kid'] = signer.keyId;
    }

    headers.addAll(jsonDecode(jsonEncode(protectedHeaders)));

    final encodedPayload = base64UrlEncode(claims);
    final encodedHeader = base64UrlEncode(headers);

    final signInput = utf8.encode('$encodedHeader.$encodedPayload');

    final signature = signer.sign(signInput);
    final encodedSignature = base64UrlEncode(signature);

    return '$encodedHeader.$encodedPayload.$encodedSignature';
  }
}
