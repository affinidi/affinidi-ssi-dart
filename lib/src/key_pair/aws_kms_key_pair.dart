import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;

import 'key_pair.dart';
import '../types.dart';

const _signatureSchemeToKmsAlgorithm = {
  SignatureScheme.rsa: kms.SigningAlgorithmSpec.rsassaPkcs1V1_5Sha_256,
};

kms.SigningAlgorithmSpec signingAlgorithmForScheme(SignatureScheme scheme) {
  return _signatureSchemeToKmsAlgorithm[scheme] ??
      (throw UnsupportedError('Unsupported signature scheme: $scheme'));
}

class KmsKeyPair implements KeyPair {
  final kms.KMS kmsClient;
  final String keyId;

  KmsKeyPair(this.kmsClient, this.keyId);

  @override
  Future<String> get id async => keyId;

  @override
  List<SignatureScheme> get supportedSignatureSchemes => [
        SignatureScheme.rsa,
      ];

  @override
  Future<Uint8List> get publicKey async {
    final response = await kmsClient.getPublicKey(keyId: keyId);
    return Uint8List.fromList(response.publicKey ?? []);
  }

  @override
  Future<KeyType> get publicKeyType async => KeyType.rsa;

  @override
  Future<Uint8List> sign(Uint8List data,
      {SignatureScheme? signatureScheme}) async {
    signatureScheme ??= SignatureScheme.rsa;

    if (signatureScheme != SignatureScheme.rsa) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only RSA is supported with SHA256");
    }

    final response = await kmsClient.sign(
      keyId: keyId,
      message: data,
      messageType: kms.MessageType.raw,
      signingAlgorithm: signingAlgorithmForScheme(signatureScheme),
    );
    return Uint8List.fromList(response.signature ?? []);
  }

  @override
  Future<bool> verify(Uint8List data, Uint8List signature,
      {SignatureScheme? signatureScheme}) async {
    signatureScheme ??= SignatureScheme.rsa;

    if (signatureScheme != SignatureScheme.rsa) {
      throw ArgumentError(
          "Unsupported signature scheme. Currently only RSA is supported with SHA256");
    }

    try {
      final response = await kmsClient.verify(
        keyId: keyId,
        message: data,
        messageType: kms.MessageType.raw,
        signature: signature,
        signingAlgorithm: signingAlgorithmForScheme(signatureScheme),
      );
      return response.signatureValid ?? false;
    } on kms.KMSInvalidSignatureException {
      return false;
    } catch (e) {
      rethrow;
    }
  }
}
