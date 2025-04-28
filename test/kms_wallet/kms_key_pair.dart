import 'dart:typed_data';

import 'package:aws_kms_api/kms-2014-11-01.dart' as kms;
import 'package:ssi/ssi.dart';

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
  @override
  final String id;
  final Uint8List _publicKeyBytes;

  KmsKeyPair._(this.kmsClient, this.id, this._publicKeyBytes);

  static Future<KmsKeyPair> generate(kms.KMS kmsClient, String id) async {
    final response = await kmsClient.getPublicKey(keyId: id);
    final publicKeyBytes = Uint8List.fromList(response.publicKey ?? []);
    return KmsKeyPair._(kmsClient, id, publicKeyBytes);
  }

  @override
  List<SignatureScheme> get supportedSignatureSchemes => [
        SignatureScheme.rsa_pkcs1_sha256,
      ];

  @override
  PublicKey get publicKey {
    return PublicKey(id, _publicKeyBytes, KeyType.rsa);
  }

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
      keyId: id,
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
        keyId: id,
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

  @override
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) async {
    // TODO: add support
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey}) async {
    //   TODO: add support
    throw UnimplementedError();
  }

  @override
  noSuchMethod(Invocation invocation) {
    return super.noSuchMethod(invocation);
  }
}
