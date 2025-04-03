import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;

enum KeyType { secp256k1, ed25519, x25519, rsa }

enum HashingAlgorithm { sha256, sha512 }

enum SignatureScheme {
  es256k("ES256K", "EcdsaSecp256k1Signature2019", KeyType.secp256k1,
      HashingAlgorithm.sha256, null), // Not supported by KMS
  eddsa("EdDSA", null, KeyType.ed25519, HashingAlgorithm.sha512,
      null), // Not supported by KMS
  ed25519sha256(null, "Ed25519Signature2020", KeyType.ed25519,
      HashingAlgorithm.sha256, null), // Not supported by KMS
  rsaSsaPkcs1V1_5Sha256(null, null, KeyType.rsa, HashingAlgorithm.sha256,
      kms.SigningAlgorithmSpec.rsassaPkcs1V1_5Sha_256);

  final String? jwtName;
  final String? w3cName;
  final KeyType keyType;
  final HashingAlgorithm hashingAlgorithm;
  final kms.SigningAlgorithmSpec? kmsSigningAlgorithm;
  const SignatureScheme(this.jwtName, this.w3cName, this.keyType,
      this.hashingAlgorithm, this.kmsSigningAlgorithm);
}

enum DidPeerType { peer0, peer2 }

abstract class JsonObject {
  JsonObject.fromJson(dynamic jsonData);
  Map<String, dynamic> toJson();
  @override
  String toString();
}
