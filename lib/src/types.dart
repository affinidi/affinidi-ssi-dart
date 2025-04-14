// ignore_for_file: constant_identifier_names

enum KeyType { secp256k1, ed25519, x25519, p256, p384, p521, rsa }

enum HashingAlgorithm { sha256, sha512 }

// Prefer snake_case for `SignatureScheme` to make it more readable

enum SignatureScheme {
  ecdsa_secp256k1_sha256("ES256K", "EcdsaSecp256k1Signature2019",
      KeyType.secp256k1, HashingAlgorithm.sha256),
  eddsa_sha512("EdDSA", "Ed25519Signature2020", KeyType.ed25519,
      HashingAlgorithm.sha512),
  ed25519_sha256("EdDSA", null, KeyType.ed25519, HashingAlgorithm.sha256),
  rsa_pkcs1_sha256(
      "RS256", "RsaSignature2018", KeyType.rsa, HashingAlgorithm.sha256);

  final String? jwtName;
  final String? w3cName;
  final KeyType keyType;
  final HashingAlgorithm hashingAlgorithm;

  const SignatureScheme(
      this.jwtName, this.w3cName, this.keyType, this.hashingAlgorithm);
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
