enum KeyType { secp256k1, ed25519, x25519, rsa }

enum HashingAlgorithm { sha256, sha512 }

enum SignatureScheme {
  es256k("ES256K", "ecdsa-secp256r1-sha256", KeyType.secp256k1,
      HashingAlgorithm.sha256),
  eddsa("EdDSA", "ed25519", KeyType.ed25519, HashingAlgorithm.sha512),
  ed25519sha256("EdDSA", "ed25519-sha256", KeyType.ed25519, HashingAlgorithm.sha256),
  rsa("RS256", "rsa-pkcs1-sha256", KeyType.rsa, HashingAlgorithm.sha256);

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
