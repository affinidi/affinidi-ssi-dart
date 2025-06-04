// ignore_for_file: constant_identifier_names

/// Supported key types.
enum KeyType {
  /// secp256k1 key type.
  secp256k1,

  /// Ed25519 key type.
  ed25519,

  /// X25519 key type.
  x25519,

  /// P-256 key type.
  p256,

  /// P-384 key type.
  p384,

  /// P-521 key type.
  p521,

  /// RSA key type.
  rsa,
}

/// Supported hashing algorithms.
enum HashingAlgorithm {
  /// SHA-256 hashing algorithm.
  sha256,

  /// SHA-512 hashing algorithm.
  sha512,
}

/// Supported signature schemes.
// Prefer snake_case for `SignatureScheme` to make it more readable

enum SignatureScheme {
  /// ECDSA with secp256k1 curve and SHA-256 hashing.
  ecdsa_secp256k1_sha256(
    alg: 'ES256K',
    crv: 'secp256k1',
    w3c: 'EcdsaSecp256k1Signature2019',
    keyType: KeyType.secp256k1,
    hashingAlgorithm: HashingAlgorithm.sha256,
  ),

  /// ECDSA with P-256 curve and SHA-256 hashing.
  ecdsa_p256_sha256(
    alg: 'ES256',
    crv: 'P-256',
    w3c: 'EcdsaSecp256r1Signature2019',
    keyType: KeyType.p256,
    hashingAlgorithm: HashingAlgorithm.sha256,
  ),

  /// EdDSA with Ed25519 curve and SHA-512 hashing.
  eddsa_sha512(
    alg: 'EdDSA',
    crv: 'Ed25519',
    w3c: null,
    keyType: KeyType.ed25519,
    hashingAlgorithm: HashingAlgorithm.sha512,
  ),

  /// Ed25519 with SHA-256 hashing.
  ed25519_sha256(
    alg: null,
    crv: 'Ed25519',
    w3c: 'Ed25519Signature2020',
    keyType: KeyType.ed25519,
    hashingAlgorithm: HashingAlgorithm.sha256,
  ),

  /// RSA with PKCS1 and SHA-256 hashing.
  rsa_pkcs1_sha256(
    alg: 'RS256',
    crv: null,
    w3c: 'RsaSignature2018',
    keyType: KeyType.rsa,
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  /// The algorithm identifier.
  final String? alg;

  /// The W3C identifier.
  final String? w3c;

  /// The curve identifier.
  final String? crv;

  /// The key type.
  final KeyType keyType;

  /// The hashing algorithm.
  final HashingAlgorithm hashingAlgorithm;

  /// Creates a [SignatureScheme] with the given parameters.
  const SignatureScheme({
    required this.alg,
    required this.w3c,
    required this.crv,
    required this.keyType,
    required this.hashingAlgorithm,
  });

  /// Creates a [SignatureScheme] from a string value.
  ///
  /// [value] The string value representing the signature scheme.
  factory SignatureScheme.fromString(String value) =>
      SignatureScheme.values.firstWhere(
        (sigSch) =>
            sigSch.name.toLowerCase() == value.toLowerCase() ||
            sigSch.alg?.toLowerCase() == value.toLowerCase() ||
            sigSch.w3c?.toLowerCase() == value.toLowerCase(),
        orElse: () => throw ArgumentError('Invalid algorithm: $value'),
      );
}

/// Maps W3C-standard cryptosuite identifiers to their corresponding SignatureScheme.
const cryptosuiteToScheme = <String, SignatureScheme>{
  'ecdsa-rdfc-2019': SignatureScheme.ecdsa_p256_sha256,
  'eddsa-rdfc-2022': SignatureScheme.eddsa_sha512,
};

/// Supported DID peer types.
enum DidPeerType {
  /// DID Peer type 0.
  peer0,

  /// DID Peer type 2.
  peer2
}

/// Abstract class for JSON objects.
abstract class JsonObject {
  /// Creates a [JsonObject] from JSON data.
  JsonObject.fromJson(dynamic jsonData);

  /// Converts the object to JSON.
  Map<String, dynamic> toJson();

  /// Returns a string representation of the object.
  @override
  String toString();
}

/// Result of a verification.
class VerificationResult {
  /// The list of errors.
  final List<String> errors;

  /// The list of warnings.
  final List<String> warnings;

  /// Creates a [VerificationResult] with the given errors and warnings.
  ///
  /// [errors] The list of errors.
  /// [warnings] The list of warnings.
  VerificationResult._({
    List<String>? errors,
    List<String>? warnings,
  })  : warnings = List.unmodifiable(warnings ?? []),
        errors = List.unmodifiable(errors ?? []);

  /// Creates a valid [VerificationResult] with optional warnings.
  ///
  /// [warnings] The list of warnings.
  VerificationResult.ok({List<String>? warnings}) : this._(warnings: warnings);

  /// Creates an invalid [VerificationResult] with the given errors and optional warnings.
  ///
  /// [errors] The list of errors.
  /// [warnings] The list of warnings.
  VerificationResult.invalid({
    required List<String> errors,
    List<String>? warnings,
  }) : this._(errors: errors, warnings: warnings);

  /// Creates a [VerificationResult] from findings with the given errors and optional warnings.
  ///
  /// [errors] The list of errors.
  /// [warnings] The list of warnings.
  VerificationResult.fromFindings({
    required List<String> errors,
    List<String>? warnings,
  }) : this._(errors: errors, warnings: warnings);

  /// Returns true if the verification result is valid.
  bool get isValid => errors.isEmpty;

  /// Returns true if the verification result has warnings.
  bool get hasWarnings => warnings.isNotEmpty;
}
