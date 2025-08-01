import 'dart:typed_data';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../util/base64_util.dart';
import 'did_document/index.dart';
import 'did_resolver.dart';
import 'universal_did_resolver.dart';
import 'verifier.dart';

/// A verifier for DID documents.
///
/// This class provides methods to verify signatures using a specified signature scheme
/// and a JSON Web Key (JWK) containing public key information.
class DidVerifier implements Verifier {
  /// The signature scheme to use for verification.
  final SignatureScheme _algorithm;

  /// The key ID used for verification.
  final String _kId;

  /// The JSON Web Key (JWK) containing the public key information.
  final Map<String, dynamic> _jwk;

  /// Creates a [DidVerifier] instance with the specified algorithm, key ID, and JWK.
  DidVerifier._(this._algorithm, this._kId, this._jwk);

  /// Creates a new [DidVerifier] instance.
  ///
  /// [algorithm] - The signature scheme to use for verification.
  /// [issuerDid] - The DID of the issuer.
  /// [kid] - The key ID to use for verification.
  /// [didResolver] - Optional DID resolver instance. If not provided, uses the default UniversalDIDResolver.
  ///
  /// Returns a new [DidVerifier] instance.
  ///
  /// Throws [SsiException] if there is an error resolving the DID document.
  static Future<DidVerifier> create({
    required SignatureScheme algorithm,
    required String issuerDid,
    String? kid,
    DidResolver? didResolver,
  }) async {
    final resolver = didResolver ?? UniversalDIDResolver.defaultResolver;
    final didDocument = await resolver.resolveDid(issuerDid);
    final kidToUse = kid ?? didDocument.assertionMethod.firstOrNull?.id;

    if (kidToUse == null) {
      throw SsiException(
        message:
            'No key ID provided and no assertion method found in DID Document for $issuerDid',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    VerificationMethod? verificationMethod;
    final fragment =
        kidToUse.contains('#') ? kidToUse.split('#').last : kidToUse;
    verificationMethod = didDocument.verificationMethod.firstWhere(
      (method) => method.id == kidToUse || method.id.endsWith('#$fragment'),
      orElse: () => throw SsiException(
        message:
            'Verification method with id $kidToUse not found in DID Document for $issuerDid',
        code: SsiExceptionType.invalidDidDocument.code,
      ),
    );

    final jwk = verificationMethod.asJwk();
    final jwkMap = Map<String, dynamic>.from(jwk.toJson());

    if (!_isAlgorithmCompatibleWithJwk(jwkMap, algorithm.alg ?? '')) {
      throw SsiException(
        message:
            'Algorithm ${algorithm.alg} is not compatible with the key type in the verification method',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    return DidVerifier._(algorithm, kidToUse, jwkMap);
  }

  @override
  bool isAllowedAlgorithm(String algorithm) {
    return _isAlgorithmCompatibleWithJwk(_jwk, algorithm);
  }

  static bool _isAlgorithmCompatibleWithJwk(
    Map<String, dynamic> jwk,
    String algorithm,
  ) {
    if (jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519') {
      return algorithm == 'EdDSA' || algorithm == 'Ed25519';
    }

    try {
      final jwtKey = JWTKey.fromJWK(jwk);
      return _isKeyCompatibleWithAlgorithm(jwtKey, algorithm);
    } catch (_) {
      return false;
    }
  }

  static bool _isKeyCompatibleWithAlgorithm(JWTKey key, String algorithm) {
    if (key is RSAPublicKey) {
      return ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
          .contains(algorithm);
    }
    if (key is ECPublicKey) {
      return ['ES256', 'ES384', 'ES512', 'ES256K'].contains(algorithm);
    }
    if (key is EdDSAPublicKey) {
      return algorithm == 'EdDSA';
    }
    if (key is SecretKey) {
      return ['HS256', 'HS384', 'HS512'].contains(algorithm);
    }
    return false;
  }

  @override
  bool verify(Uint8List data, Uint8List signature) {
    try {
      if (!_jwk.containsKey('kid')) {
        _jwk['kid'] = _kId;
      }

      if ((_jwk['kty'] == 'OKP' && _jwk['crv'] == 'Ed25519') ||
          (_jwk['alg'] == 'Ed25519')) {
        final publicKeyBytes = base64UrlNoPadDecode(_jwk['x']);
        return ed.verify(ed.PublicKey(publicKeyBytes), data, signature);
      }

      if (_jwk['crv'] == 'P-256K') {
        _jwk['crv'] = 'secp256k1';
      }

      final jwtKey = JWTKey.fromJWK(_jwk);

      return _verifyWithJWTKey(jwtKey, data, signature);
    } catch (_) {
      return false;
    }
  }

  bool _verifyWithJWTKey(JWTKey key, Uint8List data, Uint8List signature) {
    try {
      final algName = _algorithm.alg;
      if (algName == null) {
        return false;
      }
      final algorithm = JWTAlgorithm.fromName(algName);
      return algorithm.verify(key, data, signature);
    } catch (_) {
      return false;
    }
  }
}
