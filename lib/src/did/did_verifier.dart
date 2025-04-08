import 'dart:typed_data';
import 'dart:developer' as developer;

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:jose_plus/jose.dart' as jose;

import 'package:ssi/src/util/base64_util.dart';
import 'package:ssi/src/did/verifier.dart';
import '../types.dart';
import 'did_document.dart';
import 'did_resolver.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

/// Verifier for signatures using public keys from a DID Document.
//FIXME we should check proofPurpose
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
    required String kid,
    required String issuerDid,
    String? resolverAddress,
  }) async {
    try {
      final didDocument = await resolveDidDocument(
        issuerDid,
        resolverAddress: resolverAddress,
      );

      // TODO check if kid is somehow related to issuerDid

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
          code: SsiExceptionType.other.code,
        );
      }

      final Jwk jwk = verificationMethod.asJwk();
      final Map<String, dynamic> jwkMap =
          Map<String, dynamic>.from(jwk.toJson());

      developer.log('Successfully created DidVerifier', name: 'DidVerifier');

      return DidVerifier._(algorithm, kid, jwkMap);
    } catch (e) {
      developer.log('Error creating DidVerifier', name: 'DidVerifier');
      throw SsiException(
        message: 'Error creating DidVerifier',
        code: SsiExceptionType.other.code,
      );
    }
  }

  /// Checks if the specified algorithm is supported by this verifier.
  @override
  bool isAllowedAlgorithm(String algorithm) {
    if (_jwk['kty'] == 'OKP' && _jwk['crv'] == 'Ed25519') {
      return algorithm == 'EdDSA' || algorithm == 'Ed25519';
    }
    try {
      final jose.JsonWebKey? publicKey = jose.JsonWebKey.fromJson(_jwk);
      return publicKey!.usableForAlgorithm(algorithm);
    } catch (e, stackTrace) {
      developer.log('Error checking algorithm: $e',
          name: 'DidVerifier', stackTrace: stackTrace);
      return false;
    }
  }

  /// Verifies that the signature matches the data.
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
        developer.log(
          'Failed to create JsonWebKey',
          name: 'DidVerifier',
          error: 'Could not create JsonWebKey from jwkMap',
        );
        throw SsiException(
          message: 'Failed to create JsonWebKey from jwkMap',
          code: SsiExceptionType.other.code,
        );
      }

      return publicKey.verify(data, signature, algorithm: _algorithm.jwtName);
    } catch (e, stackTrace) {
      developer.log('Error verifying signature: $e',
          name: 'DidVerifier', stackTrace: stackTrace);
      return false;
    }
  }
}
