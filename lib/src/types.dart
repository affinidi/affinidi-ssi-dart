// ignore_for_file: constant_identifier_names, non_constant_identifier_names

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

/// Provides an extensible class-based interface for signature schemes.
/// Custom schemes can be registered at runtime via `SignatureScheme.registerScheme()`.
class SignatureScheme {
  /// The canonical identifier for this signature scheme.
  final String name;

  /// The JOSE algorithm identifier.
  final String? alg;

  /// The W3C linked-data proof type.
  final String? w3c;

  /// The curve identifier.
  final String? crv;

  /// The key type.
  final KeyType keyType;

  /// The hashing algorithm.
  final HashingAlgorithm hashingAlgorithm;

  const SignatureScheme._internal({
    required this.name,
    required this.alg,
    required this.w3c,
    required this.crv,
    required this.keyType,
    required this.hashingAlgorithm,
  });

  /// Public factory for creating **custom** schemes.
  /// Set `register: true` to make the new scheme discoverable via [values]
  /// and `SignatureScheme.fromString`.
  factory SignatureScheme({
    required String name,
    String? alg,
    String? w3c,
    String? crv,
    required KeyType keyType,
    required HashingAlgorithm hashingAlgorithm,
    bool register = false,
  }) {
    final scheme = SignatureScheme._internal(
      name: name,
      alg: alg,
      w3c: w3c,
      crv: crv,
      keyType: keyType,
      hashingAlgorithm: hashingAlgorithm,
    );
    if (register) registerScheme(scheme);
    return scheme;
  }

  // Built‑in schemes

  /// ECDSA with secp256k1 curve and SHA-256 hashing.
  static const SignatureScheme _ecdsaSecp256k1Sha256 =
      SignatureScheme._internal(
    name: 'ecdsa_secp256k1_sha256',
    alg: 'ES256K',
    crv: 'secp256k1',
    w3c: 'EcdsaSecp256k1Signature2019',
    keyType: KeyType.secp256k1,
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  /// ECDSA with P-256 curve and SHA-256 hashing.
  static const SignatureScheme _ecdsaP256Sha256 = SignatureScheme._internal(
    name: 'ecdsa_p256_sha256',
    alg: 'ES256',
    crv: 'P-256',
    w3c: 'EcdsaSecp256r1Signature2019',
    keyType: KeyType.p256,
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  /// EdDSA with Ed25519 curve and SHA-512 hashing.
  static const SignatureScheme _eddsaSha512 = SignatureScheme._internal(
    name: 'eddsa_sha512',
    alg: 'EdDSA',
    crv: 'Ed25519',
    w3c: null,
    keyType: KeyType.ed25519,
    hashingAlgorithm: HashingAlgorithm.sha512,
  );

  /// Ed25519 with SHA-256 hashing.
  static const SignatureScheme _ed25519Sha256 = SignatureScheme._internal(
    name: 'ed25519_sha256',
    alg: null,
    crv: 'Ed25519',
    w3c: 'Ed25519Signature2020',
    keyType: KeyType.ed25519,
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  /// RSA with PKCS1 and SHA-256 hashing.
  static const SignatureScheme _rsaPkcs1Sha256 = SignatureScheme._internal(
    name: 'rsa_pkcs1_sha256',
    alg: 'RS256',
    crv: null,
    w3c: 'RsaSignature2018',
    keyType: KeyType.rsa,
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  /// ECDSA with secp256k1 curve and SHA-256 hashing.
  static SignatureScheme get ecdsa_secp256k1_sha256 => _ecdsaSecp256k1Sha256;

  /// ECDSA with P-256 curve and SHA-256 hashing.
  static SignatureScheme get ecdsa_p256_sha256 => _ecdsaP256Sha256;

  /// EdDSA with Ed25519 curve and SHA-512 hashing.
  static SignatureScheme get eddsa_sha512 => _eddsaSha512;

  /// Ed25519 with SHA-256 hashing.
  static SignatureScheme get ed25519_sha256 => _ed25519Sha256;

  /// RSA with PKCS1 and SHA-256 hashing.
  static SignatureScheme get rsa_pkcs1_sha256 => _rsaPkcs1Sha256;

  // Registry for built‑in + user‑defined schemes
  static final List<SignatureScheme> _builtIn = [
    _ecdsaSecp256k1Sha256,
    _ecdsaP256Sha256,
    _eddsaSha512,
    _ed25519Sha256,
    _rsaPkcs1Sha256,
  ];

  static final List<SignatureScheme> _custom = <SignatureScheme>[];

  /// All registered schemes (built‑in first, then custom additions).
  static List<SignatureScheme> get values => [..._builtIn, ..._custom];

  static final Map<String, SignatureScheme> _index = {
    for (var v in _builtIn) v.name.toLowerCase(): v,
    for (var v in _builtIn) ...{
      if (v.alg != null) v.alg!.toLowerCase(): v,
      if (v.w3c != null) v.w3c!.toLowerCase(): v,
    }
  };

  /// Registers a new scheme globally.
  static void registerScheme(SignatureScheme scheme) {
    final key = scheme.name.toLowerCase();
    if (_index.containsKey(key)) {
      throw ArgumentError('SignatureScheme "$key" already exists.');
    }
    _custom.add(scheme);
    _index[key] = scheme;
    if (scheme.alg != null) _index[scheme.alg!.toLowerCase()] = scheme;
    if (scheme.w3c != null) _index[scheme.w3c!.toLowerCase()] = scheme;
  }

  /// Looks up a scheme by any known identifier (name, alg, or w3c).
  factory SignatureScheme.fromString(String value) {
    final scheme = _index[value.toLowerCase()];
    if (scheme == null) {
      throw ArgumentError('Invalid algorithm: $value');
    }
    return scheme;
  }

  /// Creates a SignatureScheme from an algorithm string with sensible defaults.
  /// Useful for handling algorithms from JWT headers that may not be pre-registered.
  static SignatureScheme fromAlgorithm(String alg) {
    try {
      return SignatureScheme.fromString(alg);
    } catch (_) {
      // Auto-detect key type and hash algorithm from common patterns
      final keyType = _detectKeyType(alg);
      final hashAlg = _detectHashAlgorithm(alg);

      return SignatureScheme(
        name: alg.toLowerCase(),
        alg: alg,
        keyType: keyType,
        hashingAlgorithm: hashAlg,
        register: true,
      );
    }
  }

  static KeyType _detectKeyType(String alg) {
    if (alg.startsWith('ES256K')) return KeyType.secp256k1;
    if (alg.startsWith('ES')) return KeyType.p256;
    if (alg.startsWith('EdDSA') || alg.contains('Ed25519')) {
      return KeyType.ed25519;
    }
    if (alg.startsWith('RS') || alg.startsWith('PS')) return KeyType.rsa;
    // Default to p256 for unknown
    return KeyType.p256;
  }

  static HashingAlgorithm _detectHashAlgorithm(String alg) {
    if (alg.contains('512')) return HashingAlgorithm.sha512;
    // Default to sha256
    return HashingAlgorithm.sha256;
  }

  @override
  String toString() => name;
}

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
