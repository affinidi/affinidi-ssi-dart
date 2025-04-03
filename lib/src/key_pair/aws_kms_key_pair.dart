import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;

import 'key_pair.dart';
import '../types.dart';

class KmsKeyPair implements KeyPair {
  final kms.KMS kmsClient;
  final String keyId;

  KmsKeyPair(this.kmsClient, this.keyId);

  @override
  Uint8List get privateKey {
    throw UnsupportedError('AWS KMS does not provide access to private keys.');
  }

  @override
  List<SignatureScheme> get supportedSignatureSchemes => [
        SignatureScheme.rsaSsaPkcs1V1_5Sha256,
      ];

  @override
  Future<Uint8List> getPublicKey() async {
    final response = await kmsClient.getPublicKey(keyId: keyId);
    return Uint8List.fromList(response.publicKey ?? []);
  }

  @override
  Future<KeyType> getKeyType() async {
    return KeyType.rsa;
  }

  @override
  Future<String> getKeyId() async {
    return keyId;
  }

  @override
  Future<Uint8List> sign(Uint8List data,
      {SignatureScheme? signatureScheme}) async {
    final selectedScheme =
        signatureScheme ?? SignatureScheme.rsaSsaPkcs1V1_5Sha256;

    if (selectedScheme.kmsSigningAlgorithm == null) {
      throw UnsupportedError(
          "Signature scheme ${selectedScheme.name} is not supported by AWS KMS.");
    }

    final response = await kmsClient.sign(
      keyId: keyId,
      message: data,
      messageType: kms.MessageType.raw,
      signingAlgorithm: selectedScheme.kmsSigningAlgorithm!,
    );

    return Uint8List.fromList(response.signature ?? []);
  }

  @override
  Future<bool> verify(Uint8List data,
      {required Uint8List signature, SignatureScheme? signatureScheme}) async {
    final selectedScheme =
        signatureScheme ?? SignatureScheme.rsaSsaPkcs1V1_5Sha256;

    if (selectedScheme.kmsSigningAlgorithm == null) {
      throw UnsupportedError(
          "Signature scheme ${selectedScheme.name} is not supported by AWS KMS.");
    }

    try {
      final response = await kmsClient.verify(
        keyId: keyId,
        message: data,
        messageType: kms.MessageType.raw,
        signature: signature,
        signingAlgorithm: selectedScheme.kmsSigningAlgorithm!,
      );
      return response.signatureValid ?? false;
    } on kms.KMSInvalidSignatureException {
      return false; // Return false when signature is invalid
    } catch (e) {
      rethrow; // Rethrow unexpected errors
    }
  }
}
