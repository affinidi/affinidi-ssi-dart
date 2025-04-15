import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';

import 'package:ssi/src/types.dart';
import 'package:ssi/src/key_pair/key_pair.dart';

const _signatureSchemeToKmsAlgorithm = {
  SignatureScheme.rsa_pkcs1_sha256:
      kms.SigningAlgorithmSpec.rsassaPkcs1V1_5Sha_256,
};

kms.SigningAlgorithmSpec signingAlgorithmForScheme(SignatureScheme scheme) {
  return _signatureSchemeToKmsAlgorithm[scheme] ??
      (throw SsiException(
        message: 'Unsupported signature scheme: $scheme',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      ));
}

class KmsKeyPair implements KeyPair {
  final kms.KMS kmsClient;
  final String keyId;

  KmsKeyPair(this.kmsClient, this.keyId);

  @override
  Future<String> get id async => keyId;

  @override
  List<SignatureScheme> get supportedSignatureSchemes => [
        SignatureScheme.rsa_pkcs1_sha256,
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
    signatureScheme ??= SignatureScheme.rsa_pkcs1_sha256;

    if (signatureScheme != SignatureScheme.rsa_pkcs1_sha256) {
      throw SsiException(
        message:
            "Unsupported signature scheme. Currently only RSA is supported with SHA256",
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
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
    signatureScheme ??= SignatureScheme.rsa_pkcs1_sha256;

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
