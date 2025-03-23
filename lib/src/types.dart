enum KeyType { secp256k1, ed25519 }

enum HashingAlgorithm { sha256, sha512 }

enum SignatureScheme {
  es256k("ES256K", "EcdsaSecp256k1Signature2019", KeyType.secp256k1,
      HashingAlgorithm.sha256);

  final String jwtName;
  final String w3cName;
  final KeyType keyType;
  final HashingAlgorithm? hashingAlgorithm;
  const SignatureScheme(
      this.jwtName, this.w3cName, this.keyType, this.hashingAlgorithm);
}
