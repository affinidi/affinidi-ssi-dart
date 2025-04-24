import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart' as ck;
import 'package:ssi/src/didcomm/didcomm_message.dart';
import 'package:ssi/src/didcomm/didcomm_message_recipient.dart';
import 'package:ssi/src/didcomm/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/jwe_header.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:ssi/ssi.dart';
import 'package:web3dart/crypto.dart';

class DidcommEncryptedMessage implements JsonObject, DidcommMessage {
  static const List<String> supportedAlgs = ['ECDH-1PU', 'ECDH-ES'];

  final JweHeader protectedHeader;
  final Uint8List tag;
  final Uint8List iv;
  final Uint8List ciphertext;
  final List<DidCommMessageRecipient> recipients;

  DidcommEncryptedMessage(
      {required this.protectedHeader,
      required this.tag,
      required this.iv,
      required this.ciphertext,
      required this.recipients});

  factory DidcommEncryptedMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);

    return DidcommEncryptedMessage(
        ciphertext: _decodeBase64(decoded['ciphertext']),
        iv: _decodeBase64(decoded['iv']),
        tag: _decodeBase64(decoded['tag']),
        protectedHeader: JweHeader.fromJson(
            jsonDecode(_decodeBase64ToString(decoded['protected']))),
        recipients: decoded['recipients']
            .map((r) => DidCommMessageRecipient.fromJson(r))
            .toList()
            .cast<DidCommMessageRecipient>());
  }

  static Future<DidcommEncryptedMessage> fromPlaintext({
    KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.ecdh1PU,
    EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.a256cbc,
    required Wallet wallet,
    required String keyId,
    required List<Map<String, dynamic>> recipientPublicKeyJwks,
    required DidcommMessage message,
  }) async {
    if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU &&
        message is DidcommPlaintextMessage &&
        message.from == null) {
      throw Exception(
          'For authcrypted messages the from-header of the plaintext message must not be null');
    }

    PublicKey publicKey = await wallet.getPublicKey(keyId);
    JweHeader jweHeader = await JweHeader.encryptedDidCommMessage(
        keyWrapAlgorithm: keyWrapAlgorithm,
        encryptionAlgorithm: encryptionAlgorithm,
        recipientPublicKeyJwks: recipientPublicKeyJwks,
        senderPublicKey: publicKey);

    ck.SymmetricKey cek = _createCek(encryptionAlgorithm);
    ck.EncryptionResult encrypted = _encryptWithCek(
        cek, encryptionAlgorithm, jweHeader.toString(), message);

    List<DidCommMessageRecipient> recipientList =
        await _encryptCekForRecipients(
            wallet: wallet,
            keyId: keyId,
            cek: cek,
            jwks: recipientPublicKeyJwks);

    return DidcommEncryptedMessage(
        recipients: recipientList,
        ciphertext: encrypted.data,
        protectedHeader: jweHeader,
        iv: encrypted.initializationVector!,
        tag: encrypted.authenticationTag!);
  }

  Future<DidcommMessage> decrypt(
      {required Wallet wallet, required String keyId}) async {
    supportedAlgs.firstWhere((alg) => protectedHeader.alg.startsWith(alg),
        orElse: () => throw Exception('Unknown algorithm'));

    elliptic.PublicKey? senderPublicKey =
        protectedHeader.isAuthCrypt() ? await _findSender() : null;

    String receiverDid = DidKey.getDid(await wallet.getPublicKey(keyId));
    DidCommMessageRecipient recipient = recipients.firstWhere(
        (r) => r.header.kid.split('#').first == receiverDid,
        orElse: () =>
            throw Exception('No matching recipient for uses key found.'));

    final decryptedCek = await wallet.decrypt(recipient.encryptedKey,
        keyId: keyId,
        publicKey: senderPublicKey != null
            ? hexToBytes(senderPublicKey.toCompressedHex())
            : null);

    ck.SymmetricKey cek = ck.SymmetricKey(keyValue: decryptedCek);
    ck.Encrypter e = _createEncrypterByEncryptionAlg(protectedHeader.enc, cek);

    var toDecrypt = ck.EncryptionResult(ciphertext,
        authenticationTag: tag,
        additionalAuthenticatedData: ascii.encode(protectedHeader.toString()),
        initializationVector: iv);

    Map<String, dynamic> message =
        jsonDecode(utf8.decode(e.decrypt(toDecrypt)));

    return DidcommMessage.fromDecrypted(message, protectedHeader);
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'ciphertext': _encodeBase64(ciphertext),
      'protected': protectedHeader.toString(),
      'tag': _encodeBase64(tag),
      'iv': _encodeBase64(iv),
      'recipients': recipients.map((r) => r.toJson()).toList(),
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  String _encodeBase64(Uint8List data) {
    return removePaddingFromBase64(base64UrlEncode(data));
  }

  static Uint8List _decodeBase64(String data) {
    return base64Decode(addPaddingToBase64(data));
  }

  static String _decodeBase64ToString(String data) {
    return utf8.decode(_decodeBase64(data));
  }

  static String _getCurveByPublicKey(PublicKey publickey) {
    if (publickey.type == KeyType.p256) {
      return 'P-256';
    } else if (publickey.type == KeyType.secp256k1) {
      return 'secp256k1';
    } else if (publickey.type == KeyType.ed25519) {
      return 'Ed25519';
    }
    throw Exception('curve for public key not implemented');
  }

  static elliptic.Curve _getCurve(PublicKey publickey) {
    if (publickey.type == KeyType.p256) {
      return elliptic.getP256();
    } else if (publickey.type == KeyType.secp256k1) {
      return elliptic.getSecp224k1();
    }
    // TODO: Ed25519
    throw Exception('curve for public key not implemented');
  }

  static _encryptCekForRecipients({
    required Wallet wallet,
    required String keyId,
    required ck.SymmetricKey cek,
    required List<Map<String, dynamic>> jwks,
  }) async {
    List<DidCommMessageRecipient> recipientList = [];

    // TODO: replace as soon as public key supports returning curve
    PublicKey publicKey = await wallet.getPublicKey(keyId);
    String senderCurve = _getCurveByPublicKey(publicKey);

    for (var key in jwks) {
      final receiverPubKey = elliptic.PublicKey(
          elliptic
              .getP256(), // TODO: replace as soon as public key supports returning curve
          bytesToUnsignedInt(base64Decode(addPaddingToBase64(key['x']!))),
          bytesToUnsignedInt(base64Decode(addPaddingToBase64(key['y']!))));

      if (key['crv'] == senderCurve) {
        final encryptedCek = await wallet.encrypt(cek.keyValue,
            keyId: keyId,
            publicKey: hexToBytes(receiverPubKey.toCompressedHex()));

        recipientList.add(DidCommMessageRecipient(
            header: DidCommMessageRecipientHeader(kid: key['kid']),
            encryptedKey: encryptedCek));
      }
    }
    return recipientList;
  }

  static _encryptWithCek(ck.SymmetricKey cek, EncryptionAlgorithm alg,
      String headers, DidcommMessage message) {
    ck.Encrypter e = _createEncrypterByEncryptionAlg(alg.value, cek);
    return e.encrypt(Uint8List.fromList(utf8.encode(message.toString())),
        additionalAuthenticatedData: ascii.encode(headers));
  }

  Future<Jwk> _findSenderJwk(String skid) async {
    DidDocument didDoc =
        (await UniversalDIDResolver.resolve(skid.split('#').first))
            .resolveKeyIds();

    return didDoc.keyAgreement.whereType<VerificationMethod>().firstWhere(
        (key) {
      String? kid = key.asJwk().toJson()['kid'];
      return kid == skid || key.id == skid;
    }, orElse: () => throw Exception('No key found in did document')).asJwk();
  }

  Future<elliptic.PublicKey> _findSender() async {
    if (protectedHeader.skid == null) {
      throw Exception('sender id needed when using AuthCrypt');
    }
    Jwk senderJwk = await _findSenderJwk(protectedHeader.skid!);

    final senderPubKey = elliptic.PublicKey.fromPoint(
        elliptic.getP256(),
        elliptic.AffinePoint.fromXY(
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(senderJwk.doc['x']!))),
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(senderJwk.doc['y']!)))));
    return senderPubKey;
  }

  static ck.SymmetricKey _createCek(EncryptionAlgorithm encryptionAlgorithm) {
    if (encryptionAlgorithm == EncryptionAlgorithm.a256cbc) {
      return ck.SymmetricKey.generate(512);
    }
    return ck.SymmetricKey.generate(256);
  }

  static ck.Encrypter _createEncrypterByEncryptionAlg(
      String? alg, ck.SymmetricKey cek) {
    if (alg == EncryptionAlgorithm.a256cbc.value) {
      return cek
          .createEncrypter(ck.algorithms.encryption.aes.cbcWithHmac.sha512);
    }

    if (alg == EncryptionAlgorithm.a256gcm.value) {
      return cek.createEncrypter(ck.algorithms.encryption.aes.gcm);
    }

    throw UnimplementedError();
  }
}
