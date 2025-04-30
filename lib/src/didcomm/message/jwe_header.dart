import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:elliptic/elliptic.dart' as ec;
import 'package:web3dart/crypto.dart' as c;

import 'package:ssi/src/did/did_key.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/key_pair/public_key.dart';
import 'package:ssi/src/types.dart';

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
    required Uint8List epkPrivate,
    required Uint8List? epkPublic,
  }) async {
    final curve = getCurveByPublicKey(senderPublicKey);
    final didDoc = DidKey.generateDocument(senderPublicKey);
    final kid = didDoc.keyAgreement.first;

    return JweHeader(
      skid: kid,
      alg: keyWrapAlgorithm.value,
      enc: encryptionAlgorithm.value,
      apv: _buildApvHeader(recipientPublicKeyJwks, curve),
      epk: _buildEpkHeader(epkPrivate, epkPublic, senderPublicKey, curve),
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
            decodeBase64ToString(jsonData['apu']),
        apv: jsonData['apv'],
        enc: jsonData['enc'],
        alg: jsonData['alg'],
        epk: jsonData['epk'],
        apu: jsonData['apu']);
  }

  bool isAuthCrypt() {
    return alg.startsWith(KeyWrapAlgorithm.ecdh1PU.value);
  }

  bool isAnonCrypt() {
    return alg.startsWith(KeyWrapAlgorithm.ecdhES.value);
  }

  static String? _buildApuHeader(
    KeyWrapAlgorithm keyWrapAlgorithm,
    String keyId,
  ) {
    return keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU
        ? encodeBase64(utf8.encode(keyId))
        : null;
  }

  static List<String> _getReceiverKeyIds(
    List<Map<String, dynamic>> jwks,
    String curve,
  ) {
    final receiverKeyIds = jwks
        .where((key) => key['crv'] == curve)
        .map((key) => key['kid'])
        .toList();
    receiverKeyIds.sort();
    return receiverKeyIds.toList().cast<String>();
  }

  static _buildApvHeader(
    List<Map<String, dynamic>> jwks,
    String curve,
  ) {
    final receiverKeyIds = _getReceiverKeyIds(jwks, curve);
    final keyIdString = receiverKeyIds.join('.');

    if (keyIdString.isEmpty) {
      throw Exception('Cant find keys with matching crv parameter');
    }

    return removePaddingFromBase64(
        base64UrlEncode(sha256.convert(utf8.encode(keyIdString)).bytes));
  }

  static Map<String, dynamic> _buildEpkHeader(
    Uint8List privateKeyBytes,
    Uint8List? epkPublic,
    PublicKey senderPublicKey,
    String curve,
  ) {
    if (isSecp256OrPCurve(curve)) {
      final privateKey = getPrivateKeyFromBytes(privateKeyBytes,
          keyType: senderPublicKey.type);

      final crvPoint = _getPublicKeyPoint(privateKey.publicKey);
      return {
        'crv': curve,
        'x': crvPoint.X,
        'y': crvPoint.Y,
        'kty': 'EC',
      };
    }

    if (isXCurve(curve)) {
      final X = removePaddingFromBase64(base64UrlEncode(epkPublic!.toList()));
      return {'crv': curve, 'x': X, 'kty': 'OKP'};
    }

    throw Exception('Unknown key type for EPK header');
  }

  static ({String X, String Y}) _getPublicKeyPoint(ec.PublicKey publicKey) {
    final X = encodeBase64(publicKey.X < BigInt.zero
        ? c.intToBytes(publicKey.X)
        : c.unsignedIntToBytes(publicKey.X));

    final Y = encodeBase64(publicKey.Y < BigInt.zero
        ? c.intToBytes(publicKey.Y)
        : c.unsignedIntToBytes(publicKey.Y));

    return (X: X, Y: Y);
  }
}
