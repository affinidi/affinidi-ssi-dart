import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:aws_signature_v4/aws_signature_v4.dart';

import 'key_pair.dart';
import '../types.dart';

class KmsKeyPair implements KeyPair {
  final kms.KMS kmsClient;
  final String keyId;

  KmsKeyPair(this.kmsClient, this.keyId);

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
  Future<Uint8List> sign(Uint8List data, {SignatureScheme? signatureScheme}) async {
    final response = await kmsClient.sign(
      keyId: keyId,
      message: data,
      messageType: kms.MessageType.raw,
      signingAlgorithm: kms.SigningAlgorithmSpec.rsassaPkcs1V1_5Sha_256,
    );
    return Uint8List.fromList(response.signature ?? []);
  }

  // @override
  Future<bool> verify(Uint8List data, {required Uint8List signature, SignatureScheme? signatureScheme}) async {
    try {
      final response = await kmsClient.verify(
        keyId: keyId,
        message: data,
        messageType: kms.MessageType.raw,
        signature: signature,
        signingAlgorithm: kms.SigningAlgorithmSpec.rsassaPkcs1V1_5Sha_256,
      );
      return response.signatureValid ?? false;
    } on kms.KMSInvalidSignatureException {
      return false; // Return false when signature is invalid
    } catch (e) {
      print('Error verifying signature: $e');
      rethrow; // Rethrow unexpected errors
    }
  }
}
