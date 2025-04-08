import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:jose_plus/jose.dart' as jose;

import 'did_document.dart';
import 'did_resolver.dart';
import 'public_key_utils.dart';
import 'verifier.dart';

class DidVerifier implements Verifier {
  final String _algorithm;
  final String _kId;
  final Map<String, dynamic> _jwk;

  DidVerifier._(this._algorithm, this._kId, this._jwk);

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

    final Jwk jwk = verificationMethod.asJwk();
    final Map<String, dynamic> jwkMap = Map<String, dynamic>.from(jwk.toJson());

    return DidVerifier._(algorithm, kid, jwkMap);
  }

  @override
  bool isAllowedAlgorithm(String algorithm) {
    if (_jwk['kty'] == 'OKP' && _jwk['crv'] == 'Ed25519') {
      return algorithm == 'EdDSA' || algorithm == 'Ed25519';
    }

    try {
      final jose.JsonWebKey? publicKey = jose.JsonWebKey.fromJson(_jwk);
      return publicKey!.usableForAlgorithm(algorithm);
    } catch (_) {
      return false;
    }
  }

  @override
  bool verify(Uint8List data, Uint8List signature) {
    try {
      if (!_jwk.containsKey('kid')) {
        _jwk['kid'] = _kId;
      }

      // Handle Ed25519 keys
      if (_jwk['kty'] == 'OKP' && _jwk['crv'] == 'Ed25519') {
        if (_algorithm != 'EdDSA') {
          return false;
        }
        final publicKeyBytes =
            base64Url.decode(addPaddingToBase64(_jwk['x'] as String));
        return ed.verify(ed.PublicKey(publicKeyBytes), data, signature);
      }

      // For other key types, use the jose library
      final publicKey = jose.JsonWebKey.fromJson(_jwk);

      if (publicKey == null) {
        throw ArgumentError('failed to create JsonWebKey from jwkMap');
      }

      return publicKey.verify(data, signature, algorithm: _algorithm);
    } catch (_) {
      return false;
    }
  }
}
