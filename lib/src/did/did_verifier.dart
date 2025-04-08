import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:jose_plus/jose.dart' as jose;
import 'package:ssi/src/did/verifier.dart';
import 'package:ssi/src/util/base64_util.dart';

import '../types.dart';
import 'did_document.dart';
import 'did_resolver.dart';

//FIXME we should check proofPurpose
class DidVerifier implements Verifier {
  final SignatureScheme _algorithm;
  final String _kId;
  final Map<String, dynamic> _jwk;

  DidVerifier._(this._algorithm, this._kId, this._jwk);

  static Future<DidVerifier> create({
    required SignatureScheme algorithm,
    required String kid,
    required String issuerDid,
    String? resolverAddress,
  }) async {
    final didDocument = await resolveDidDocument(
      issuerDid,
      resolverAddress: resolverAddress,
    );

    // TODO check if kid is somehow related to issuerDid

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
        if (_algorithm.jwtName != 'EdDSA') {
          return false;
        }

        final publicKeyBytes = base64UrlNoPadDecode(_jwk['x']);
        return ed.verify(ed.PublicKey(publicKeyBytes), data, signature);
      }

      // the library uses the old crv value P-256K
      if (_jwk['crv'] == 'secp256k1') {
        _jwk['crv'] = 'P-256K';
      }

      // For other key types, use the jose library
      final publicKey = jose.JsonWebKey.fromJson(_jwk);

      if (publicKey == null) {
        throw ArgumentError('failed to create JsonWebKey from jwkMap');
      }

      return publicKey.verify(data, signature, algorithm: _algorithm.jwtName);
    } catch (_) {
      return false;
    }
  }
}
