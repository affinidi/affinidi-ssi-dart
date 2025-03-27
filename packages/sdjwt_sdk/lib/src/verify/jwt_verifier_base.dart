import 'dart:convert';
import 'dart:typed_data';

import 'package:jose_plus/jose.dart';
import 'package:sdjwt_sdk/src/verify/verifier.dart';
import 'package:sdjwt_sdk/src/utils/common.dart';

/// A mixin that provides common JWT verification functionality.
///
/// This mixin includes methods for verifying JWT signatures, time-based claims,
/// and confirmation claims (cnf).
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
mixin JwtVerifier {
  /// Verifies the signature of a JWT using the provided key.
  ///
  /// Parameters:
  /// - **[serialized]**: The JWT string to verify.
  /// - **[verifier]**: The [Verifier] to use for verification.
  ///
  /// Returns the verified JWT object if successful.
  /// Throws an exception if verification fails.
  bool verifyJwt({
    required String serialized,
    required Verifier verifier,
  }) {
    final jws = JsonWebSignature.fromCompactSerialization(serialized);

    final header = jws.recipients.first.header;
    final data = jws.data;
    final signature = Uint8List.fromList(jws.recipients[0].data);

    // Verify that the algorithm is supported by the verifier.
    final alg = header.algorithm;
    if (alg == null || !verifier.isAllowedAlgorithm(alg)) {
      throw Exception('JWT verification failed: Supported alg not found');
    }

    final encodedPayload = base64UrlEncode(data);
    final encodedHeader = base64UrlEncode(header);

    final signInput = utf8.encode('$encodedHeader.$encodedPayload');

    return verifier.verify(signInput, signature);
  }

  /// Verifies time-based claims in the JWT payload.
  ///
  /// Checks that:
  /// - The expiration time (exp) is in the future
  /// - The issued at time (iat) is in the past
  /// - The not before time (nbf), if present, is in the past
  ///
  /// Parameters:
  /// - **[payload]**: The JWT payload containing the claims.
  ///
  /// Returns true if all time-based claims are valid, false otherwise.
  /// Throws an exception if required claims are missing.
  bool verifyTimeBasedClaims(Map<String, dynamic> payload) {
    final now = jwtNow();

    final exp = payload['exp'];
    if (exp == null) {
      throw Exception('Expiry claim (exp) is missing');
    }
    if (exp < now) return false;

    final iat = payload['iat'];
    if (iat == null) {
      throw Exception('Issued at claim (iat) is missing');
    }
    if (iat > now) return false;

    final nbf = payload['nbf'];
    if (nbf != null && nbf > now) return false;

    return true;
  }
}
