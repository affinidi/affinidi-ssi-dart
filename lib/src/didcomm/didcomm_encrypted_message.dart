import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart' as ck;
import 'package:ssi/src/didcomm/_ecdh_profile.dart';
import 'package:ssi/src/didcomm/didcomm_message.dart';
import 'package:ssi/src/didcomm/didcomm_message_recipient.dart';
import 'package:ssi/src/didcomm/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/_ecdh1pu.dart';
import 'package:ssi/src/didcomm/jwe_header.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:elliptic/elliptic.dart' as ec;
import 'package:ssi/src/key_pair/_ecdh_utils.dart';
import 'package:ssi/ssi.dart';
import 'package:web3dart/crypto.dart';
import 'package:x25519/x25519.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

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

  static ({Uint8List privateKeyBytes, Uint8List? publicKeyBytes})
      _getEpkPrivateKey(PublicKey publicKey) {
    ec.EllipticCurve c;
    if (publicKey.type == KeyType.p256) {
      return (
        privateKeyBytes:
            Uint8List.fromList(ec.getP256().generatePrivateKey().bytes),
        publicKeyBytes: null
      );
    } else if (publicKey.type == KeyType.secp256k1) {
      return (
        privateKeyBytes:
            Uint8List.fromList(ec.getSecp256k1().generatePrivateKey().bytes),
        publicKeyBytes: null
      );
    } else if (publicKey.type == KeyType.ed25519) {
      final (keyPair, privateKeyBytes) = Ed25519KeyPair.generate();
      return (
        privateKeyBytes: privateKeyBytes,
        publicKeyBytes: keyPair.publicKey.bytes
      );
    } else {
      throw Exception('NOT SUPPORTED ENCRYPT');
    }
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
    final epkKeyPair = _getEpkPrivateKey(publicKey);

    JweHeader jweHeader = await JweHeader.encryptedDidCommMessage(
        keyWrapAlgorithm: keyWrapAlgorithm,
        encryptionAlgorithm: encryptionAlgorithm,
        recipientPublicKeyJwks: recipientPublicKeyJwks,
        senderPublicKey: publicKey,
        epkPrivate: epkKeyPair.privateKeyBytes,
        epkPublic: epkKeyPair.publicKeyBytes);

    ck.SymmetricKey cek = _createCek(encryptionAlgorithm);
    ck.EncryptionResult encrypted = _encryptWithCek(
        cek, encryptionAlgorithm, jweHeader.toString(), message);

    List<DidCommMessageRecipient> recipientList =
        await _encryptCekForRecipients(
            keyWrapAlgorithm: keyWrapAlgorithm,
            authenticationTag: encrypted.authenticationTag!,
            wallet: wallet,
            keyId: keyId,
            cek: cek,
            epkPrivateKey: epkKeyPair.privateKeyBytes,
            recipientPublicKeyJwks: recipientPublicKeyJwks,
            jweHeader: jweHeader);

    return DidcommEncryptedMessage(
        recipients: recipientList,
        ciphertext: encrypted.data,
        protectedHeader: jweHeader,
        iv: encrypted.initializationVector!,
        tag: encrypted.authenticationTag!);
  }

  Future<DidcommMessage> decrypt({
    required Wallet wallet,
    required String keyId,
  }) async {
    _isAlgorhythmSupportedForDecryption();
    Uint8List decryptedCek = await _decryptCek(wallet: wallet, keyId: keyId);

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

  decryptWithPrivateJwk(Map privateKeyJwk, String receiverDid) async {
    Map<String, dynamic> publicKeyJwk = privateKeyJwk['verificationMethod']
        .firstWhere(
            (m) => m['publicKeyJwk']?['crv'] == protectedHeader.epk['crv'],
            orElse: () => throw Exception(''))['publicKeyJwk'];

    ec.PrivateKey privateKey =
        getPrivateKeyFromJwk(publicKeyJwk, protectedHeader.epk);

    DidCommMessageRecipient recipient = recipients.firstWhere(
        (r) => r.header.kid.split('#').first == receiverDid,
        orElse: () =>
            throw Exception('No matching recipient for uses key found.'));

    late ECDH1PU ecdh1pu;
    if (publicKeyJwk['crv'].startsWith('P') ||
        publicKeyJwk['crv'].startsWith('secp256k1')) {
      ec.PublicKey? senderPublicKey =
          protectedHeader.isAuthCrypt() ? await _findSender() : null;

      ec.Curve c = getCurveByJwk(publicKeyJwk);
      ec.PublicKey epkPublic = ec.PublicKey.fromPoint(
          c,
          ec.AffinePoint.fromXY(
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(protectedHeader.epk['x']))),
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(protectedHeader.epk['y'])))));

      ecdh1pu = ECDH1PU_Elliptic(
        public1: epkPublic,
        public2: senderPublicKey!,
        authenticationTag: tag,
        keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
        apu: protectedHeader.apu!,
        apv: protectedHeader.apv,
      );
    } else if (publicKeyJwk['crv'].startsWith('X')) {
      // elliptic.PublicKey? senderPublicKey =
      //     protectedHeader.isAuthCrypt() ? await _findSender() : null;
      Uint8List senderPublicKey =
          base64Decode(addPaddingToBase64(protectedHeader.epk['x']));

      Uint8List epkPublic =
          base64Decode(addPaddingToBase64(protectedHeader.epk!['x']));

      ecdh1pu = ECDH1PU_X25519(
        public1: epkPublic,
        public2: senderPublicKey!,
        private1: privateKey.bytes,
        authenticationTag: tag,
        keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
        apu: protectedHeader.apu!,
        apv: protectedHeader.apv,
      );
    }

    final decryptedCek = ecdh1pu.decryptData(
        privateKey: Uint8List.fromList(privateKey.bytes),
        data: recipient.encryptedKey);

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

  Future<Uint8List> _decryptCek({
    required Wallet wallet,
    required String keyId,
  }) async {
    PublicKey receiverPublicKey = await wallet.getPublicKey(keyId);

    DidCommMessageRecipient recipient =
        _findMessageRecipientByPublicKey(receiverPublicKey);

    if (protectedHeader.isAnonCrypt()) {
      ec.PublicKey? senderPublicKey =
          protectedHeader.isAuthCrypt() ? await _findSender() : null;

      return wallet.decrypt(
        recipient.encryptedKey,
        keyId: keyId,
        publicKey: senderPublicKey != null
            ? hexToBytes(senderPublicKey.toCompressedHex())
            : null,
      );
    } else if (protectedHeader.isAuthCrypt()) {
      if (protectedHeader.skid == null) {
        throw Exception('sender id needed when using AuthCrypt');
      }

      late ECDH1PU ecdh1puProfile;
      late Uint8List senderPublicKeyBytes;

      Jwk senderJwk = await _findSenderJwk(protectedHeader.skid!);
      if (isSecp256OrPCurve(protectedHeader.epk['crv'])) {
        ec.PublicKey? senderPublicKey = publicKeyFromPoint(
            curve: getCurveByJwk(senderJwk.toJson()),
            x: senderJwk.doc['x']!,
            y: senderJwk.doc['y']!);

        ecdh1puProfile = ECDHProfile.buildElliptic(
          receiverPublicKey: receiverPublicKey,
          senderPublicKey: senderPublicKey,
          authenticationTag: tag,
          epk: protectedHeader.epk,
          apu: protectedHeader.apu!,
          apv: protectedHeader.apv,
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
        );

        senderPublicKeyBytes = hexToBytes(senderPublicKey.toCompressedHex());
      } else if (protectedHeader.epk['crv'].startsWith('X')) {
        final epkPublicKey =
            base64Decode(addPaddingToBase64(protectedHeader.epk!['x']));
        senderPublicKeyBytes =
            base64Decode(addPaddingToBase64(senderJwk.toJson()['x']!));

        ecdh1puProfile = ECDH1PU_X25519(
          public1: epkPublicKey,
          public2: senderPublicKeyBytes,
          authenticationTag: tag,
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
          apu: protectedHeader.apu!,
          apv: protectedHeader.apv,
        );
      }

      return wallet.decrypt(
        recipient.encryptedKey,
        keyId: keyId,
        publicKey: senderPublicKeyBytes,
        ecdhProfile: ecdh1puProfile,
      );
    }

    throw Exception('Decryption not supported');
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

  static _encryptCekForRecipients({
    required KeyWrapAlgorithm keyWrapAlgorithm,
    required Wallet wallet,
    required String keyId,
    required ck.SymmetricKey cek,
    required Uint8List authenticationTag,
    required List<Map<String, dynamic>> recipientPublicKeyJwks,
    required JweHeader jweHeader,
    required Uint8List epkPrivateKey,
  }) async {
    List<DidCommMessageRecipient> recipientList = [];
    PublicKey publicKey = await wallet.getPublicKey(keyId);

    String senderCurve = getCurveByPublicKey(publicKey);
    DidDocument didDoc = DidKey.generateDocument(publicKey);

    // TODO: ECDH-ES

    var c;
    if (publicKey.type == KeyType.p256) {
      c = ec.getP256();
    } else if (publicKey.type == KeyType.secp256k1) {
      c = ec.getSecp256k1();
    }

    for (var key in recipientPublicKeyJwks) {
      if (key['crv'] == senderCurve) {
        // if (protectedHeader.alg.startsWith('ECDH-1PU'))

        late Uint8List encryptedCek;
        if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdhES) {
          Uint8List receiverPubKey;

          if (key['crv'].startsWith('P') ||
              key['crv'].startsWith('secp256k1')) {
            receiverPubKey = hexToBytes(ec.PublicKey(
                    c,
                    bytesToUnsignedInt(
                        base64Decode(addPaddingToBase64(key['x']!))),
                    bytesToUnsignedInt(
                        base64Decode(addPaddingToBase64(key['y']!))))
                .toCompressedHex());
          } else if (key['crv'].startsWith('X')) {
            receiverPubKey = base64Decode(addPaddingToBase64(key['x']!));
          } else {
            throw Exception('Not implemented');
          }

          encryptedCek = await wallet.encrypt(cek.keyValue,
              keyId: keyId, publicKey: receiverPubKey);
        } else if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU) {
          late ECDH1PU ecdh1pu;
          late Uint8List receiverPubKey;

          if (key['crv'].startsWith('P') ||
              key['crv'].startsWith('secp256k1')) {
            ec.PublicKey pub = ec.PublicKey(
                c,
                bytesToUnsignedInt(base64Decode(addPaddingToBase64(key['x']!))),
                bytesToUnsignedInt(
                    base64Decode(addPaddingToBase64(key['y']!))));

            ecdh1pu = ECDH1PU_Elliptic(
                authenticationTag: authenticationTag,
                keyWrapAlgorithm: keyWrapAlgorithm,
                apu: removePaddingFromBase64(
                    base64Encode(utf8.encode(didDoc.verificationMethod[0].id))),
                apv: jweHeader.apv,
                public1: pub,
                public2: pub,
                private1: ec.PrivateKey.fromBytes(c, epkPrivateKey));
            receiverPubKey = hexToBytes(pub.toCompressedHex());
          } else if (key['crv'].startsWith('X')) {
            receiverPubKey = base64Decode(addPaddingToBase64(key['x']!));

            ecdh1pu = ECDH1PU_X25519(
                authenticationTag: authenticationTag,
                keyWrapAlgorithm: keyWrapAlgorithm,
                apu: removePaddingFromBase64(
                    base64Encode(utf8.encode(didDoc.verificationMethod[0].id))),
                apv: jweHeader.apv,
                public1: receiverPubKey,
                public2: receiverPubKey,
                private1: epkPrivateKey);
          } else {
            throw Exception('Not implemented');
          }

          encryptedCek = await wallet.encrypt(cek.keyValue,
              keyId: keyId, publicKey: receiverPubKey, ecdhProfile: ecdh1pu);
        }

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

  Future<ec.PublicKey> _findSender() async {
    if (protectedHeader.skid == null) {
      throw Exception('sender id needed when using AuthCrypt');
    }
    Jwk senderJwk = await _findSenderJwk(protectedHeader.skid!);

    late ec.Curve e;
    if (protectedHeader.epk['crv'] == 'secp256k1') {
      e = ec.getSecp256k1();
    } else if (protectedHeader.epk['crv'] == 'P-256') {
      e = ec.getP256();
    } else {
      throw Exception('Not supported');
    }

    final senderPubKey = ec.PublicKey.fromPoint(
        e,
        ec.AffinePoint.fromXY(
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

  void _isAlgorhythmSupportedForDecryption() {
    supportedAlgs.firstWhere((alg) => protectedHeader.alg.startsWith(alg),
        orElse: () => throw Exception('Unknown algorithm'));
  }

  DidCommMessageRecipient _findMessageRecipientByPublicKey(
    PublicKey receiverPublicKey,
  ) {
    String receiverDid = DidKey.getDid(receiverPublicKey);
    return recipients.firstWhere(
        (r) => r.header.kid.split('#').first == receiverDid,
        orElse: () =>
            throw Exception('No matching recipient for uses key found.'));
  }
}
