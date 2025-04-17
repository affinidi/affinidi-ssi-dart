// ignore_for_file: constant_identifier_names

enum KeyType { secp256k1, ed25519, x25519, p256, p384, p521, rsa }

enum HashingAlgorithm { sha256, sha512 }

// Prefer snake_case for `SignatureScheme` to make it more readable

enum SignatureScheme {
  ecdsa_secp256k1_sha256(
    alg: "ES256K",
    crv: "secp256k1",
    w3c: "EcdsaSecp256k1Signature2019",
    keyType: KeyType.secp256k1,
    hashingAlgorithm: HashingAlgorithm.sha256,
  ),
  ecdsa_p256_sha256(
    alg: "ES256",
    crv: "P-256",
    w3c: "EcdsaSecp256r1Signature2019",
    keyType: KeyType.p256,
    hashingAlgorithm: HashingAlgorithm.sha256,
  ),
  eddsa_sha512(
    alg: "EdDSA",
    crv: "Ed25519",
    w3c: null,
    keyType: KeyType.ed25519,
    hashingAlgorithm: HashingAlgorithm.sha512,
  ),
  ed25519_sha256(
    alg: null,
    crv: "Ed25519",
    w3c: "Ed25519Signature2020",
    keyType: KeyType.ed25519,
    hashingAlgorithm: HashingAlgorithm.sha256,
  ),
  rsa_pkcs1_sha256(
    alg: "RS256",
    crv: null,
    w3c: "RsaSignature2018",
    keyType: KeyType.rsa,
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  final String? alg;
  final String? w3c;
  final String? crv;
  final KeyType keyType;
  final HashingAlgorithm hashingAlgorithm;

  const SignatureScheme({
    required this.alg,
    required this.w3c,
    required this.crv,
    required this.keyType,
    required this.hashingAlgorithm,
  });

  factory SignatureScheme.fromString(String value) =>
      SignatureScheme.values.firstWhere(
        (sigSch) =>
            sigSch.name.toLowerCase() == value.toLowerCase() ||
            sigSch.alg?.toLowerCase() == value.toLowerCase() ||
            sigSch.w3c?.toLowerCase() == value.toLowerCase(),
        orElse: () => throw ArgumentError('Invalid algorithm: $value'),
      );
}

enum DidPeerType { peer0, peer2 }

abstract class JsonObject {
  JsonObject.fromJson(dynamic jsonData);

  Map<String, dynamic> toJson();

  @override
  String toString();
}

/// Result of a verification
class VerificationResult {
  final List<String> errors;
  final List<String> warnings;

  VerificationResult._({
    List<String>? errors,
    List<String>? warnings,
  })  : warnings = List.unmodifiable(warnings ?? []),
        errors = List.unmodifiable(errors ?? []);

  VerificationResult.ok({List<String>? warnings}) : this._(warnings: warnings);

  VerificationResult.invalid({
    required List<String> errors,
    List<String>? warnings,
  }) : this._(errors: errors, warnings: warnings);

  VerificationResult.fromFindings({
    required List<String> errors,
    List<String>? warnings,
  }) : this._(errors: errors, warnings: warnings);

  bool get isValid => errors.isEmpty;

  bool get hasWarnings => warnings.isNotEmpty;
}
