import 'dart:typed_data';

import 'package:jose_plus/jose.dart';
import 'package:sdjwt_sdk/src/sign/signer.dart';
import 'package:sdjwt_sdk/src/verify/verifier.dart';

/// Bundled Crypto Algorithms.
enum SdJwtSignAlgorithm {
  /// HMAC using SHA-256.
  hs256(JsonWebAlgorithm.hs256),

  /// HMAC using SHA-384.
  hs384(JsonWebAlgorithm.hs384),

  /// HMAC using SHA-512.
  hs512(JsonWebAlgorithm.hs512),

  /// RSASSA-PKCS1-v1_5 using SHA-256.
  rs256(JsonWebAlgorithm.rs256),

  /// RSASSA-PKCS1-v1_5 using SHA-384.
  rs384(JsonWebAlgorithm.rs384),

  /// RSASSA-PKCS1-v1_5 using SHA-512.
  rs512(JsonWebAlgorithm.rs512),

  /// ECDSA using P-256 and SHA-256.
  es256(JsonWebAlgorithm.es256),

  /// ECDSA using P-384 and SHA-384.
  es384(JsonWebAlgorithm.es384),

  /// ECDSA using P-521 and SHA-512.
  es512(JsonWebAlgorithm.es512),

  /// ECDSA using P-256 and SHA-256.
  es256k(JsonWebAlgorithm.es256k);

  /// A reference to the internally wrapped JWA instance.
  final JsonWebAlgorithm _jwa;

  /// Create an enum entry of supported SdJwtAlgorithms.
  const SdJwtSignAlgorithm(this._jwa);

  /// Lookup the SdJwtAlgorithms enum from a given algorithm name.
  factory SdJwtSignAlgorithm.fromString(String value) {
    return SdJwtSignAlgorithm.values.firstWhere(
      (jwa) => jwa._jwa.name == value,
      orElse: () => throw ArgumentError('Invalid algorithm: $value'),
    );
  }

  /// Lookup the SdJwtAlgorithm enum from a given elliptic curve. Relevant only for ECDSA based algorithms.
  factory SdJwtSignAlgorithm.fromCurve(String curve) {
    final normalizedCurve = normalizeCurve(curve);

    return SdJwtSignAlgorithm.values.firstWhere(
      (jwa) => jwa._jwa.curve == normalizedCurve,
      orElse: () => throw ArgumentError('Invalid algorithm: $curve'),
    );
  }

  /// Standardize the name of the elliptic curve from different variants to a single standards compliant name.
  static String normalizeCurve(String curve) {
    switch (curve.toUpperCase()) {
      case 'SECP256K1':
        return SdJwtSignAlgorithm.es256k.curve ?? curve;
      default:
        return curve;
    }
  }

  /// Checks if the given JWK (ECDSA based) or the Algorithm name is among the bundled algorithms.
  static bool isSupported(String alg) {
    // Checks if the algorithm is among the bundled algorithms.
    try {
      SdJwtSignAlgorithm.fromString(alg);
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  String toString() => _jwa.name;

  /// Return the name of the curve used by the ECDSA based algorithm. Returns null for other algorithms.
  String? get curve => _jwa.curve;

  /// The string representation of The Internet Assigned Numbers Authority
  /// (IANA) name.
  String get ianaName => _jwa.name;
}

/// Abstract class representing an SD-JWT cryptographic key.
///  Subclasses:
/// - `SdPrivateKey` (for signing).
/// - `SdPublicKey` (for verification).
abstract class SdKey {
  /// The internally wrapped JWK.
  final JsonWebKey _key;

  /// the algorithm implemented by the given key.
  final SdJwtSignAlgorithm alg;

  /// Creates an SD key from the provided key data in various supported formats and algorithm.
  ///
  /// Parameters:
  /// - **[keyData]**: The key data, either as a PEM string or a JWK map.
  /// - **[alg]**: The algorithm to use with this key.
  SdKey(dynamic keyData, this.alg) : _key = _createJsonWebKey(keyData, alg);

  /// Parses keyData from various supported formats
  static JsonWebKey _createJsonWebKey(
    dynamic keyData,
    SdJwtSignAlgorithm alg,
  ) {
    if (keyData is String) {
      return _createJsonWebKeyFromPem(keyData, alg);
    } else if (keyData is Map<String, dynamic>) {
      return _createJsonWebKeyFromJWK(keyData, alg)!;
    } else {
      throw ArgumentError(
          'Invalid key data type. Expected String or Map<String, dynamic>.');
    }
  }

  /// Parses key data in PEM format
  static JsonWebKey _createJsonWebKeyFromPem(
    String pem,
    SdJwtSignAlgorithm alg,
  ) {
    return JsonWebKey.fromPem(pem);
  }

  /// Parses key data in JWK format
  static JsonWebKey? _createJsonWebKeyFromJWK(
    Map<String, dynamic> jwk,
    SdJwtSignAlgorithm alg,
  ) {
    return JsonWebKey.fromJson(jwk);
  }

  /// Gets the IANA name for the algorithm used with this key.
  ///
  /// Returns the IANA standard name for the algorithm.
  String algIanaName() => alg.ianaName;

  @override
  String toString() => _key.toString();

  /// Returns the JSON Web Key version of the key
  Map<String, dynamic> toJson() => _key.toJson();
}

/// Represents a private key for signing SD-JWTs.
///
/// This class is used for signing operations in the SD-JWT workflow.
class SdPrivateKey extends SdKey {
  /// Creates a private key from the provided key data and algorithm.
  ///
  /// Parameters:
  /// - **[key]**: The key data, either as a PEM string or a JWK map.
  /// - **[alg]**: The algorithm to use with this key.
  SdPrivateKey(super.key, super.alg);
}

/// Represents a public key for verifying SD-JWTs.
///
/// This class is used for verification operations in the SD-JWT workflow.
class SdPublicKey extends SdKey {
  /// Creates a public key from the provided key data and algorithm.
  ///
  /// Parameters:
  /// - **[key]**: The key data, either as a PEM string or a JWK map.
  /// - **[alg]**: The algorithm to use with this key.
  SdPublicKey(super.key, super.alg);
}

/// Implements the [Signer] for bundled algorithms and supported private key formats.
class SDKeySigner implements Signer {
  final SdPrivateKey _privateKey;

  @override
  final String? keyId;

  /// Creates the signer for the given [SdPrivateKey]
  ///
  /// Parameters:
  /// - **[_privateKey]**: The [SdPrivateKey] that can be used for signing
  /// - **[keyId]**: (optional) Any additional verification Id
  SDKeySigner(this._privateKey, {this.keyId});

  @override
  Uint8List sign(Uint8List input) {
    final sig =
        _privateKey._key.sign(input, algorithm: _privateKey.algIanaName());
    return Uint8List.fromList(sig);
  }

  @override
  String get algIanaName => _privateKey.alg.ianaName;
}

/// Implements the [Signer] for bundled algorithms and supported public key formats.
class SDKeyVerifier implements Verifier {
  final SdPublicKey _publicKey;

  /// Creates the verifier for the given [SdPublicKey].
  /// The public key of the JWT's issuer can be deduced as needed using any appropriate method.
  ///
  /// Parameters:
  /// - **[_publicKey]**: The [SdPublicKey] that can be used for verifying
  SDKeyVerifier(this._publicKey);

  /// Verify the signature bytes, for the given data bytes using the [SdPublicKey] and it's [SdJwtSignAlgorithm].
  ///
  /// Parameters:
  /// - **[data]**: The data bytes
  /// - **[signature]**: The signature bytes
  ///
  /// Returns whether the signature is correct
  @override
  bool verify(Uint8List data, Uint8List signature) {
    return _publicKey._key
        .verify(data, signature, algorithm: _publicKey.algIanaName());
  }

  /// This Verifier can be used with any of the bundled algorithms.
  @override
  bool isAllowedAlgorithm(String algorithm) {
    return SdJwtSignAlgorithm.isSupported(algorithm);
  }
}
