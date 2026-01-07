import 'dart:convert';

import '../did/did_signer.dart';
import 'base64_util.dart';

/// Utility class for handling JWT operations.
class JwtUtil {
  DidSigner _signer;
  Map<String, dynamic> header;

  /// Creates a JwtUtil instance with the given [signer].
  JwtUtil(DidSigner signer)
      : _signer = signer,
        header = {
          'alg': signer.signatureScheme.alg,
          'kid': signer.keyId,
          'typ': 'JWT',
        };

  /// Signs a JWT with the given [payload].
  Future<Map<String, String>> signJwt(Map<String, dynamic> payload) async {
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


    // final header = <String, dynamic>{
    //   'alg': signer.signatureScheme.alg,
    //   'kid': signer.keyId,
    //   'typ': 'JWT',
    // };
    // payload['iss'] = issuerId;

