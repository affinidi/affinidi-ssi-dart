import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:ssi/src/didcomm/types.dart';

import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/ssi.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:web3dart/crypto.dart' as c;

class JweHeader implements JsonObject {
  final String? skid;
  final String typ = 'application/didcomm-encrypted+json';
  final String apv;
  final String enc;
  final String alg;
  final Map<String, dynamic> epk;
  final String? apu;

  JweHeader(
      {this.skid,
      required this.apv,
      required this.enc,
      required this.alg,
      required this.epk,
      required this.apu});

  static encryptedDidCommMessage({
    required KeyWrapAlgorithm keyWrapAlgorithm,
    required EncryptionAlgorithm encryptionAlgorithm,
    required List<Map<String, dynamic>> recipientPublicKeyJwks,
    required PublicKey senderPublicKey,
  }) async {
    DidDocument didDoc = DidKey.generateDocument(senderPublicKey);
    String kid = didDoc.keyAgreement.first;

    late String curve;
    if (senderPublicKey.type == KeyType.p256) {
      curve = 'P-256';
    } else if (senderPublicKey.type == KeyType.secp256k1) {
      curve = 'secp256k1';
    } else if (senderPublicKey.type == KeyType.ed25519) {
      curve = 'X25519';
    }

    return JweHeader(
      skid: kid,
      alg: keyWrapAlgorithm.value,
      enc: encryptionAlgorithm.value,
      apv: _buildApvHeader(recipientPublicKeyJwks, curve),
      epk: _buildEpkHeader(senderPublicKey, curve),
      apu: _buildApuHeader(keyWrapAlgorithm, kid),
    );
  }

  @override
  String toString() {
    return removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(this))));
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'enc': enc,
      'alg': alg,
      'apu': apu,
      'skid': skid,
      'typ': typ,
      'apv': apv,
      'epk': epk,
    };
  }

  factory JweHeader.fromJson(dynamic jsonData) {
    return JweHeader(
        skid: jsonData['skid'] ??
            jsonData['apu'] ??
            utf8.decode(base64Decode(addPaddingToBase64(jsonData['apu']))),
        apv: jsonData['apv'],
        enc: jsonData['enc'],
        alg: jsonData['alg'],
        epk: jsonData['epk'],
        apu: jsonData['apu']);
  }

  bool isAuthCrypt() {
    return alg.startsWith('ECDH-1PU');
  }

  static String? _buildApuHeader(
    KeyWrapAlgorithm keyWrapAlgorithm,
    String keyId,
  ) {
    return keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU
        ? removePaddingFromBase64(base64UrlEncode(utf8.encode(keyId)))
        : null;
  }

  static List<String> _getReceiverKeyIds(
    List<Map<String, dynamic>> jwks,
    String curve,
  ) {
    List<String> receiverKeyIds = jwks
        .where((key) => key['crv'] == curve)
        .map((key) => key['kid'])
        .toList()
        .cast<String>();
    receiverKeyIds.sort();
    return receiverKeyIds;
  }

  static _buildApvHeader(
    List<Map<String, dynamic>> jwks,
    String curve,
  ) {
    List<dynamic> receiverKeyIds = _getReceiverKeyIds(jwks, curve);
    String keyIdString = receiverKeyIds.join('.');

    if (keyIdString.isEmpty) {
      throw Exception('Cant find keys with matching crv parameter');
    }

    return removePaddingFromBase64(
        base64UrlEncode(sha256.convert(utf8.encode(keyIdString)).bytes));
  }

  static Map<String, dynamic> _buildEpkHeader(
    PublicKey publicKey,
    String curve,
  ) {
    elliptic.Curve? crv;
    String kty;

    if (publicKey.type == KeyType.p256) {
      crv = elliptic.getP256();
      kty = 'P-256';
    } else if (publicKey.type == KeyType.secp256k1) {
      crv = elliptic.getSecp256k1();
      kty = 'EC';
    } else if (publicKey.type == KeyType.ed25519) {
      kty = 'OKP';
    } else {
      throw Exception('Not implemented');
    }

    Map<String, dynamic> epkJwk = {'kty': kty, 'crv': curve};
    if (crv != null) {
      // TODO: can be removed as soon as public key exposes X, Y
      elliptic.PublicKey ecPub = elliptic.PublicKey.fromHex(
        crv,
        c.bytesToHex(publicKey.bytes),
      );

      epkJwk['x'] = removePaddingFromBase64(base64UrlEncode(
          ecPub.X < BigInt.zero
              ? c.intToBytes(ecPub.X)
              : c.unsignedIntToBytes(ecPub.X)));
      epkJwk['y'] = removePaddingFromBase64(base64UrlEncode(
          ecPub.Y < BigInt.zero
              ? c.intToBytes(ecPub.Y)
              : c.unsignedIntToBytes(ecPub.Y)));
    } else {
      epkJwk['x'] = removePaddingFromBase64(base64UrlEncode(publicKey.bytes));
    }

    return epkJwk;
  }
}
