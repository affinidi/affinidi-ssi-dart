import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:x25519/x25519.dart' as x25519;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:affinidi_tdk_cryptography/affinidi_tdk_cryptography.dart';

import '../digest_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'key_pair.dart';

import './_const.dart';

class Ed25519KeyPair implements KeyPair {
  final String _keyId;
  final dynamic _privateKey;
  final CryptographyService _cryptographyService;

  Ed25519KeyPair({
    required dynamic privateKey,
    required String keyId,
  })  : _privateKey = privateKey,
        _keyId = keyId,
        _cryptographyService = CryptographyService();

  @override
  Future<String> get id => Future.value(_keyId);

  @override
  Future<Uint8List> get publicKey => Future.value(
        Uint8List.fromList(
          ed.public(_privateKey).bytes,
        ),
      );

  @override
  Future<KeyType> get publicKeyType => Future.value(KeyType.ed25519);

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519_sha256;
    if (signatureScheme != SignatureScheme.ed25519_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 is supported.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );
    return ed.sign(_privateKey, digest);
  }

  @override
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) async {
    signatureScheme ??= SignatureScheme.ed25519_sha256;

    if (signatureScheme != SignatureScheme.ed25519_sha256) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Only ed25519_sha256 is supported',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    final digest = DigestUtils.getDigest(
      data,
      hashingAlgorithm: signatureScheme.hashingAlgorithm,
    );

    return ed.verify(ed.public(_privateKey), digest, signature);
  }

  Uint8List getSeed() => ed.seed(_privateKey);

  @override
  List<SignatureScheme> get supportedSignatureSchemes =>
      const [SignatureScheme.ed25519_sha256];

  List<int> generateEphemeralPubKey() {
    var eKeyPair = x25519.generateKeyPair();
    var publicKey = eKeyPair.publicKey;

    return publicKey;
  }

  Future<Uint8List> computeEcdhSecret(List<int> publicKey) async {
    var privateKeyForX25519 =
        _privateKey.bytes.sublist(0, COMPRESSED_PUB_KEY_LENGTH);
    final secret = x25519.X25519(privateKeyForX25519, publicKey);
    return Future.value(Uint8List.fromList(secret));
  }

  // NOTE: using without conversion to and from x25519 https://www.reddit.com/r/crypto/comments/j02krx/using_ed25519_with_ecdh/?rdt=43776
  // @override
  encrypt(Uint8List data, {Uint8List? publicKey}) async {
    final privateKey = _privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    List<int> publicKeyToUse;
    if (publicKey == null) {
      publicKeyToUse = await generateEphemeralPubKey();
    } else {
      publicKeyToUse = publicKey;
    }

    final sharedSecret = await computeEcdhSecret(publicKeyToUse);

    final algorithm = crypto.Hkdf(
      hmac: crypto.Hmac.sha256(),
      outputLength: 32,
    );

    final secretKey = crypto.SecretKey(sharedSecret);

    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      nonce: STATIC_HKD_NONCE,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    Uint8List symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final encryptedData =
        await _cryptographyService.encryptToBytes(symmetricKey, data);

    return Uint8List.fromList(publicKeyToUse + encryptedData);
  }

  // @override
  decrypt(Uint8List ivAndBytes, {Uint8List? publicKey}) async {
    final privateKey = _privateKey;
    if (privateKey == null) {
      throw ArgumentError('Private key is null');
    }

    // Extract the ephemeral public key and the encrypted data
    final ephemeralPublicKeyBytes =
        ivAndBytes.sublist(0, COMPRESSED_PUB_KEY_LENGTH);
    final encryptedData = ivAndBytes
        .sublist(COMPRESSED_PUB_KEY_LENGTH); // The rest is the encrypted data

    var pubKeyToUse;
    if (publicKey == null) {
      pubKeyToUse = ephemeralPublicKeyBytes;
    } else {
      pubKeyToUse = publicKey;
    }

    final sharedSecret = await computeEcdhSecret(pubKeyToUse);

    final algorithm = crypto.Hkdf(
      hmac: crypto.Hmac.sha256(),
      outputLength: 32,
    );
    final secretKey = crypto.SecretKey(sharedSecret);
    final derivedKey = await algorithm.deriveKey(
      secretKey: secretKey,
      nonce: STATIC_HKD_NONCE,
    );

    final derivedKeyBytes = await derivedKey.extractBytes();

    Uint8List symmetricKey = Uint8List.fromList(derivedKeyBytes);

    final decryptedData = await _cryptographyService.decryptFromBytes(
        symmetricKey, encryptedData);

    if (decryptedData == null) {
      throw UnimplementedError('Decryption failed, bytes are null');
    }

    return decryptedData;
  }
}
