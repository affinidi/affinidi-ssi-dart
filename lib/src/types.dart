enum KeyType { secp256k1, ed25519, x25519, p256, p384, p521, rsa }

enum HashingAlgorithm { sha256, sha512 }

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
