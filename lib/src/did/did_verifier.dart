import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:jose_plus/jose.dart' as jose;
import 'package:ssi/src/did/verifier.dart';
import 'package:ssi/src/util/base64_util.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'did_document.dart';
import 'universal_did_resolver.dart';

class DidVerifier implements Verifier {
  /// The signature scheme to use for verification.
  final SignatureScheme _algorithm;

  /// The key ID used for verification.
  final String _kId;

  /// The JSON Web Key (JWK) containing the public key information.
  final Map<String, dynamic> _jwk;

  DidVerifier._(this._algorithm, this._kId, this._jwk);

  /// Creates a new [DidVerifier] instance.
  ///
  /// [algorithm] - The signature scheme to use for verification.
  /// [kid] - The key ID to use for verification.
  /// [issuerDid] - The DID of the issuer.
  /// [resolverAddress] - Optional address of the DID resolver.
  ///
  /// Returns a new [DidVerifier] instance.
  ///
  /// Throws [SsiException] if there is an error resolving the DID document.
  static Future<DidVerifier> create({
    required SignatureScheme algorithm,
    String? kid,
    required String issuerDid,
    String? resolverAddress,
  }) async {
    final didDocument = await UniversalDIDResolver.resolve(
      issuerDid,
      resolverAddress: resolverAddress,
    );

    kid ??= didDocument.assertionMethod[0] as String;

    VerificationMethod? verificationMethod;
    for (final method in didDocument.verificationMethod) {
      if (method.id == kid || method.id.endsWith('#$kid')) {
        verificationMethod = method;
        break;
      }
    }

    if (verificationMethod == null) {
      throw SsiException(
        message:
            'Verification method with id $kid not found in DID Document for $issuerDid',
        code: SsiExceptionType.invalidDidDocument.code,
      );
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
        if (_algorithm.alg != 'EdDSA') {
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
        throw SsiException(
          message: 'failed to create JsonWebKey from jwkMap',
          code: SsiExceptionType.invalidDidDocument.code,
        );
      }

      return publicKey.verify(data, signature, algorithm: _algorithm.alg);
    } catch (_) {
      return false;
    }
  }
}
