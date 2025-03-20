enum KeyType { secp256k1, p256 }

enum HashingAlgorithm { sha256, sha512 }

enum AlgorithmSuite {
  es256k("ES256K", "EcdsaSecp256k1Signature2019");

  final String jwtName;
  final String w3cName;
  const AlgorithmSuite(this.jwtName, this.w3cName);
}
