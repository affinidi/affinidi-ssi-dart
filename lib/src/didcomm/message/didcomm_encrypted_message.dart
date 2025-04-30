import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/did/did_document.dart';
import 'package:ssi/src/did/did_key.dart';
import 'package:ssi/src/did/universal_did_resolver.dart';
import 'package:ssi/src/didcomm/message/ecdh/ecdh_es.dart';
import 'package:ssi/src/key_pair/public_key.dart';
import 'package:ssi/src/wallet/wallet.dart';
import 'package:web3dart/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart' as ck;
import 'package:elliptic/elliptic.dart' as ec;

import 'package:ssi/src/didcomm/message/ecdh/ecdh_profile.dart';
import 'package:ssi/src/didcomm/message/didcomm_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_message_recipient.dart';
import 'package:ssi/src/didcomm/message/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/message/ecdh/ecdh_1pu.dart';
import 'package:ssi/src/didcomm/message/jwe_header.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';

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
    final decoded = credentialToMap(message);

    return DidcommEncryptedMessage(
        ciphertext: decodeBase64(decoded['ciphertext']),
        iv: decodeBase64(decoded['iv']),
        tag: decodeBase64(decoded['tag']),
        protectedHeader: JweHeader.fromJson(
            jsonDecode(decodeBase64ToString(decoded['protected']))),
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

    final publicKey = await wallet.getPublicKey(keyId);
    final epkKeyPair = getEphemeralPrivateKey(publicKey);

    JweHeader jweHeader = await JweHeader.encryptedDidCommMessage(
        keyWrapAlgorithm: keyWrapAlgorithm,
        encryptionAlgorithm: encryptionAlgorithm,
        recipientPublicKeyJwks: recipientPublicKeyJwks,
        senderPublicKey: publicKey,
        epkPrivate: epkKeyPair.privateKeyBytes,
        epkPublic: epkKeyPair.publicKeyBytes);

    final cek = _createCek(encryptionAlgorithm);
    final encrypted = _encryptWithCek(
        cek, encryptionAlgorithm, jweHeader.toString(), message);

    if (encrypted.initializationVector == null) {
      throw Exception('Initialization vector not set after encryption of CEK');
    }

    if (encrypted.authenticationTag == null) {
      throw Exception('Authentication tag not set after encryption of CEK');
    }

    final recipientList = await _encryptCekForRecipients(
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

    final cek = ck.SymmetricKey(keyValue: decryptedCek);
    final e = _createEncrypterByEncryptionAlg(protectedHeader.enc, cek);

    final toDecrypt = ck.EncryptionResult(ciphertext,
        authenticationTag: tag,
        additionalAuthenticatedData: ascii.encode(protectedHeader.toString()),
        initializationVector: iv);

    final message = jsonDecode(utf8.decode(e.decrypt(toDecrypt)));

    return DidcommMessage.fromDecrypted(message, protectedHeader);
  }

  decryptWithPrivateJwk(Map privateKeyJwk, String receiverDid) async {
    final decryptedCek =
        await _decryptCekWithPrivateJwk(privateKeyJwk, receiverDid);

    final cek = ck.SymmetricKey(keyValue: decryptedCek);
    final e = _createEncrypterByEncryptionAlg(protectedHeader.enc, cek);

    final encrypted = ck.EncryptionResult(ciphertext,
        authenticationTag: tag,
        additionalAuthenticatedData: ascii.encode(protectedHeader.toString()),
        initializationVector: iv);

    final message = jsonDecode(utf8.decode(e.decrypt(encrypted)));
    return DidcommMessage.fromDecrypted(message, protectedHeader);
  }

  static Future<List<DidCommMessageRecipient>> _encryptCekForRecipients({
    required KeyWrapAlgorithm keyWrapAlgorithm,
    required Wallet wallet,
    required String keyId,
    required ck.SymmetricKey cek,
    required Uint8List authenticationTag,
    required List<Map<String, dynamic>> recipientPublicKeyJwks,
    required JweHeader jweHeader,
    required Uint8List epkPrivateKey,
  }) async {
    final List<DidCommMessageRecipient> recipientList = [];
    final publicKey = await wallet.getPublicKey(keyId);
    final senderCurve = getCurveByPublicKey(publicKey);

    for (var recipientPublicKeyJwk in recipientPublicKeyJwks) {
      if (recipientPublicKeyJwk['crv'] != senderCurve) continue;

      late Uint8List encryptedCek;
      if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdhES) {
        encryptedCek = await _encryptCekUsingECDH_ES(
          cek,
          wallet: wallet,
          keyId: keyId,
          recipientPublicKeyJwk: recipientPublicKeyJwk,
          publicKey: publicKey,
          epkPrivateKey: epkPrivateKey,
          jweHeader: jweHeader,
        );
      } else if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU) {
        encryptedCek = await _encryptCekUsingECDH_1PU(cek,
            wallet: wallet,
            keyId: keyId,
            recipientPublicKeyJwk: recipientPublicKeyJwk,
            publicKey: publicKey,
            jweHeader: jweHeader,
            epkPrivateKey: epkPrivateKey,
            authenticationTag: authenticationTag,
            keyWrapAlgorithm: keyWrapAlgorithm);
      } else {
        throw Exception('Key wrap algorithm "$keyWrapAlgorithm" not supported');
      }

      recipientList.add(DidCommMessageRecipient(
          header:
              DidCommMessageRecipientHeader(kid: recipientPublicKeyJwk['kid']),
          encryptedKey: encryptedCek));
    }
    return recipientList;
  }

  static Future<Uint8List> _encryptCekUsingECDH_ES(
    ck.SymmetricKey cek, {
    required Wallet wallet,
    required String keyId,
    required Map<String, dynamic> recipientPublicKeyJwk,
    required PublicKey publicKey,
    required Uint8List epkPrivateKey,
    required JweHeader jweHeader,
  }) {
    late ECDHES ecdhProfile;
    if (isSecp256OrPCurve(jweHeader.epk['crv'])) {
      ec.PublicKey recipientPublicKey = publicKeyFromPoint(
        curve: getEllipticCurveByPublicKey(publicKey),
        x: recipientPublicKeyJwk['x'],
        y: recipientPublicKeyJwk['y'],
      );

      ecdhProfile = ECDHES_Elliptic(
        privateKeyBytes: epkPrivateKey,
        publicKey: recipientPublicKey,
        apv: jweHeader.apv,
        enc: jweHeader.enc,
      );
    } else if (isXCurve(jweHeader.epk['crv'])) {
      ecdhProfile = ECDHES_X25519(
        privateKey: epkPrivateKey,
        publicKey: publicKeyBytesFromJwk(recipientPublicKeyJwk),
        apv: jweHeader.apv,
        enc: jweHeader.enc,
      );
    } else {
      throw Exception('Curve "${jweHeader.epk['crv']}" not supported.');
    }

    return wallet.encrypt(cek.keyValue,
        keyId: keyId,
        publicKey: publicKeyBytesFromJwk(recipientPublicKeyJwk),
        ecdhProfile: ecdhProfile);
  }

  static Future<Uint8List> _encryptCekUsingECDH_1PU(ck.SymmetricKey cek,
      {required Wallet wallet,
      required String keyId,
      required Map<String, dynamic> recipientPublicKeyJwk,
      required PublicKey publicKey,
      required Uint8List authenticationTag,
      required KeyWrapAlgorithm keyWrapAlgorithm,
      required JweHeader jweHeader,
      required Uint8List epkPrivateKey}) {
    final didDoc = DidKey.generateDocument(publicKey);

    if (isSecp256OrPCurve(recipientPublicKeyJwk['crv'])) {
      final receiverPubKey = publicKeyFromPoint(
        curve: getEllipticCurveByPublicKey(publicKey),
        x: recipientPublicKeyJwk['x'],
        y: recipientPublicKeyJwk['y'],
      );

      final ecdh1pu = ECDH1PU_Elliptic(
          authenticationTag: authenticationTag,
          keyWrapAlgorithm: keyWrapAlgorithm,
          apu: removePaddingFromBase64(
              base64Encode(utf8.encode(didDoc.verificationMethod[0].id))),
          apv: jweHeader.apv,
          public1: receiverPubKey,
          public2: receiverPubKey,
          private1: ec.PrivateKey.fromBytes(
            getEllipticCurveByPublicKey(publicKey),
            epkPrivateKey,
          ));

      return wallet.encrypt(cek.keyValue,
          keyId: keyId,
          publicKey: hexToBytes(receiverPubKey.toCompressedHex()),
          ecdhProfile: ecdh1pu);
    } else if (isXCurve(recipientPublicKeyJwk['crv'])) {
      final receiverPubKeyBytes = publicKeyBytesFromJwk(recipientPublicKeyJwk);

      final ecdh1pu = ECDH1PU_X25519(
          authenticationTag: authenticationTag,
          keyWrapAlgorithm: keyWrapAlgorithm,
          apu: removePaddingFromBase64(
              base64Encode(utf8.encode(didDoc.verificationMethod[0].id))),
          apv: jweHeader.apv,
          public1: receiverPubKeyBytes,
          public2: receiverPubKeyBytes,
          private1: epkPrivateKey);

      return wallet.encrypt(cek.keyValue,
          keyId: keyId, publicKey: receiverPubKeyBytes, ecdhProfile: ecdh1pu);
    } else {
      throw Exception('Curve "${recipientPublicKeyJwk['crv']}" not supported');
    }
  }

  static ck.EncryptionResult _encryptWithCek(
    ck.SymmetricKey cek,
    EncryptionAlgorithm alg,
    String headers,
    DidcommMessage message,
  ) {
    final e = _createEncrypterByEncryptionAlg(alg.value, cek);
    return e.encrypt(Uint8List.fromList(utf8.encode(message.toString())),
        additionalAuthenticatedData: ascii.encode(headers));
  }

  Future<Uint8List> _decryptCek({
    required Wallet wallet,
    required String keyId,
  }) async {
    final receiverPublicKey = await wallet.getPublicKey(keyId);
    final recipient = _findMessageRecipientByPublicKey(receiverPublicKey);

    if (protectedHeader.isAnonCrypt()) {
      late ECDHES ecdhProfile;
      if (isSecp256OrPCurve(protectedHeader.epk['crv'])) {
        final epkPublicKey = publicKeyFromPoint(
            curve: getCurveByJwk(protectedHeader.epk),
            x: protectedHeader.epk['x'],
            y: protectedHeader.epk['y']);

        ecdhProfile = ECDHES_Elliptic(
          publicKey: epkPublicKey,
          enc: protectedHeader.enc,
          apv: protectedHeader.apv,
        );
      } else if (isXCurve(protectedHeader.epk['crv'])) {
        ecdhProfile = ECDHES_X25519(
            apv: protectedHeader.apv,
            enc: protectedHeader.enc,
            publicKey: publicKeyBytesFromJwk(protectedHeader.epk));
      } else {
        throw Exception('Curve "${protectedHeader.epk['crv']}" not supported');
      }

      return wallet.decrypt(recipient.encryptedKey,
          keyId: keyId, ecdhProfile: ecdhProfile);
    } else if (protectedHeader.isAuthCrypt()) {
      if (protectedHeader.skid == null) {
        throw Exception('sender id needed when using AuthCrypt');
      }

      if (protectedHeader.apu == null) {
        throw Exception('Protected header apu not set');
      }

      late ECDH1PU ecdh1puProfile;
      late Uint8List senderPublicKeyBytes;

      final senderJwk = await _findSenderJwk(protectedHeader.skid!);
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
      } else if (isXCurve(protectedHeader.epk['crv'])) {
        senderPublicKeyBytes = base64Decode(senderJwk.toJson()['x']!);

        ecdh1puProfile = ECDHProfile.buildX25519(
          senderPublicKeyBytes: senderPublicKeyBytes,
          authenticationTag: tag,
          epk: protectedHeader.epk,
          apu: protectedHeader.apu!,
          apv: protectedHeader.apv,
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
        );
      }

      return wallet.decrypt(
        recipient.encryptedKey,
        keyId: keyId,
        publicKey: senderPublicKeyBytes,
        ecdhProfile: ecdh1puProfile,
      );
    }

    throw Exception('Curve ${protectedHeader.epk['crv']} not supported');
  }

  Future<Uint8List> _decryptCekWithPrivateJwk(
    Map privateKeyJwk,
    String receiverDid,
  ) async {
    final publicKeyJwk = privateKeyJwk['verificationMethod'].firstWhere(
        (m) => m['publicKeyJwk']?['crv'] == protectedHeader.epk['crv'],
        orElse: () => throw Exception(''))['publicKeyJwk'];
    final privateKey = getPrivateKeyFromJwk(publicKeyJwk, protectedHeader.epk);
    final recipient = _findMessageRecipientByDid(receiverDid);

    if (protectedHeader.skid == null) {
      throw Exception('Protected header skid is not set');
    }

    final senderJwk = await _findSenderJwk(protectedHeader.skid!);

    if (protectedHeader.skid == null) {
      throw Exception('Protected header apu is not set');
    }

    if (isSecp256OrPCurve(publicKeyJwk['crv'])) {
      final receiverCurve = getCurveByJwk(publicKeyJwk);
      final senderPublicKey = publicKeyFromPoint(
          curve: getCurveByJwk(senderJwk.toJson()),
          x: senderJwk.doc['x']!,
          y: senderJwk.doc['y']!);

      final ecdh1pu = ECDHProfile.buildEllipticWithReceiverCurve(
        curve: receiverCurve,
        senderPublicKey: senderPublicKey,
        authenticationTag: tag,
        keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
        apu: protectedHeader.apu!,
        apv: protectedHeader.apv,
        epk: protectedHeader.epk,
      );

      return ecdh1pu.decryptData(
          privateKey: Uint8List.fromList(privateKey.bytes),
          data: recipient.encryptedKey);
    } else if (isXCurve(publicKeyJwk['crv'])) {
      final senderPublicKey = base64Decode(protectedHeader.epk['x']);
      final epkPublic = base64Decode(protectedHeader.epk['x']);

      final ecdh1pu = ECDH1PU_X25519(
        public1: epkPublic,
        public2: senderPublicKey,
        private1: privateKey.bytes,
        authenticationTag: tag,
        keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
        apu: protectedHeader.apu!,
        apv: protectedHeader.apv,
      );

      return ecdh1pu.decryptData(
          privateKey: Uint8List.fromList(privateKey.bytes),
          data: recipient.encryptedKey);
    } else {
      throw Exception('Curve ${publicKeyJwk['crv']} not supported');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'ciphertext': encodeBase64(ciphertext),
      'protected': protectedHeader.toString(),
      'tag': encodeBase64(tag),
      'iv': encodeBase64(iv),
      'recipients': recipients.map((r) => r.toJson()).toList(),
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  Future<Jwk> _findSenderJwk(String skid) async {
    final didDoc = (await UniversalDIDResolver.resolve(skid.split('#').first))
        .resolveKeyIds();

    return didDoc.keyAgreement.whereType<VerificationMethod>().firstWhere(
        (key) {
      final kid = key.asJwk().toJson()['kid'];
      return kid == skid || key.id == skid;
    }, orElse: () => throw Exception('No key found in did document')).asJwk();
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
    final receiverDid = DidKey.getDid(receiverPublicKey);
    return _findMessageRecipientByDid(receiverDid);
  }

  DidCommMessageRecipient _findMessageRecipientByDid(String receiverDid) {
    return recipients.firstWhere(
        (r) => r.header.kid.split('#').first == receiverDid,
        orElse: () =>
            throw Exception('No matching recipient for uses key found.'));
  }
}
