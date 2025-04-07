import 'dart:typed_data';

import 'package:jose_plus/jose.dart';

import 'did_document.dart';
import 'did_resolver.dart';
import 'verifier.dart';

class DidVerifier implements Verifier {
  final String _algorithm;
  final String _kid;
  final VerificationMethod _verificationMethod;

  DidVerifier._(this._algorithm, this._kid, this._verificationMethod);

  @override
  String get keyId => _kid;

  static Future<DidVerifier> create({
    required String algorithm,
    required String kid,
    required String issuerDid,
    String? resolverAddress,
  }) async {
    final didDocument =
        await resolveDidDocument(issuerDid, resolverAddress: resolverAddress);

    VerificationMethod? verificationMethod;
    for (var method in didDocument.verificationMethod) {
      if (method.id == kid || method.id.endsWith('#$kid')) {
        verificationMethod = method;
        break;
      }
    }

    if (verificationMethod == null) {
      throw ArgumentError(
          'Verification method with id $kid not found in DID Document for $issuerDid');
    }

    return DidVerifier._(algorithm, kid, verificationMethod);
  }

  @override
  bool isAllowedAlgorithm(String algorithm) {
    final jwk = _verificationMethod.asJwk();
    final crv = jwk.toJson()['crv'];

    switch (crv) {
      case 'Ed25519':
        return algorithm == 'EdDSA' || algorithm == 'Ed25519';
      case 'secp256k1':
        return algorithm == 'ES256K';
      case 'P-256':
        return algorithm == 'ES256';
      default:
        return false;
    }
  }

  @override
  bool verify(Uint8List data, Uint8List signature) {
    try {
      final Jwk jwk = _verificationMethod.asJwk();
      final Map<String, dynamic> jwkMap =
          Map<String, dynamic>.from(jwk.toJson());

      if (!jwkMap.containsKey('kid')) {
        jwkMap['kid'] = _verificationMethod.id;
      }

      final publicKey = JsonWebKey.fromJson(jwkMap);

      if (publicKey == null) {
        throw ArgumentError('failed to create JsonWebKey from jwkMap');
      }

      return publicKey.verify(data, signature, algorithm: _algorithm);
    } catch (e) {
      return false;
    }
  }
}
