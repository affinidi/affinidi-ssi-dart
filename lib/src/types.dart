enum KeyType { secp256k1, ed25519, x25519 }

enum HashingAlgorithm { sha256, sha512 }

enum SignatureScheme {
  es256k("ES256K", "EcdsaSecp256k1Signature2019", KeyType.secp256k1,
      HashingAlgorithm.sha256),
  // TODO: Validate JWT and W3C algorithm names for ed25519
  eddsa("EdDSA", null, KeyType.ed25519, HashingAlgorithm.sha512),
  ed25519sha256(
      null, "Ed25519Signature2020", KeyType.ed25519, HashingAlgorithm.sha256);

  final String? jwtName;
  final String? w3cName;
  final KeyType keyType;
  final HashingAlgorithm hashingAlgorithm;
  const SignatureScheme(
      this.jwtName, this.w3cName, this.keyType, this.hashingAlgorithm);
}

enum DidPeerType { peer0, peer2 }
