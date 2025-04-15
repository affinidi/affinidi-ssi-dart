import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:jose_plus/jose.dart' as jose;

import '../did/verifier.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../util/base64_util.dart';
import 'did_document.dart';
import 'did_resolver.dart';

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

    // TODO(FTL-20742) check if kid is somehow related to issuerDid

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

    final Jwk jwk;
    try {
      jwk = verificationMethod.asJwk();
    } catch (e) {
      throw SsiException(
        message: 'Failed to parse verification method as JWK',
        originalMessage: e.toString(),
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
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

      if (_jwk['kty'] == 'OKP' && _jwk['crv'] == 'Ed25519') {
        if (_algorithm.jwtName != 'EdDSA') {
          return false;
        }
        final publicKeyBytes = base64UrlNoPadDecode(_jwk['x']);
        return ed.verify(ed.PublicKey(publicKeyBytes), data, signature);
      }

      if (_jwk['crv'] == 'secp256k1') {
        _jwk['crv'] = 'P-256K';
      }

      final publicKey = jose.JsonWebKey.fromJson(_jwk);

      if (publicKey == null) {
        throw SsiException(
          message: 'failed to create JsonWebKey from jwkMap',
          code: SsiExceptionType.invalidDidDocument.code,
        );
      }

      return publicKey.verify(data, signature, algorithm: _algorithm.jwtName);
    } catch (e) {
      return false;
    }
  }
}
