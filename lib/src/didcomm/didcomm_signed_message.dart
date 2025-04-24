import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/src/didcomm/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/didcomm_message.dart';
import 'package:ssi/src/didcomm/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/jws_header.dart';
import 'package:ssi/src/didcomm/signature_object.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/ssi.dart';

class DidcommSignedMessage implements JsonObject, DidcommMessage {
  late DidcommMessage payload;
  List<SignatureObject>? signatures;
  String? _base64Payload;

  DidcommSignedMessage({required this.payload, this.signatures});

  DidcommSignedMessage.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('payload')) {
      _base64Payload = sig['payload'];
      var decodedPayload =
          utf8.decode(base64Decode(addPaddingToBase64(sig['payload'])));
      try {
        payload = DidcommSignedMessage.fromJson(decodedPayload);
      } catch (e) {
        try {
          payload = DidcommPlaintextMessage.fromJson(decodedPayload);
        } catch (e) {
          try {
            payload = DidcommEncryptedMessage.fromJson(decodedPayload);
          } catch (e) {
            throw Exception('Unknown message type');
          }
        }
      }
    } else {
      throw Exception('payload is needed in jws');
    }
    if (sig.containsKey('signatures')) {
      List tmp = sig['signatures'];
      if (tmp.isNotEmpty) {
        signatures = [];
        for (var s in tmp) {
          signatures!.add(SignatureObject.fromJson(s));
        }
      } else {
        throw Exception('Empty Signatures');
      }
    } else {
      throw Exception('signature property is needed in jws');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['payload'] = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(payload.toString())));

    if (signatures != null) {
      List sigs = [];
      for (var s in signatures!) {
        sigs.add(s.toJson());
      }
      jsonObject['signatures'] = sigs;
    }

    return jsonObject;
  }

  static Future<DidcommSignedMessage> fromPlaintext(
      {required Wallet wallet,
      required String keyId,
      required DidcommPlaintextMessage message}) async {
    DidcommSignedMessage signedMessage = DidcommSignedMessage(payload: message);
    await signedMessage.sign(wallet, [keyId]);
    return signedMessage;
  }

  Future<DidcommEncryptedMessage> encrypt({
    KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.ecdh1PU,
    EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.a256cbc,
    required Wallet wallet,
    required String keyId,
    required List<Map<String, dynamic>> recipientPublicKeyJwks,
  }) {
    return DidcommEncryptedMessage.fromPlaintext(
        keyWrapAlgorithm: keyWrapAlgorithm,
        encryptionAlgorithm: encryptionAlgorithm,
        wallet: wallet,
        keyId: keyId,
        recipientPublicKeyJwks: recipientPublicKeyJwks,
        message: this);
  }

  Future<void> sign(Wallet wallet, List<String> keyIds) async {
    signatures ??= [];
    for (var keyId in keyIds) {
      SignatureScheme scheme =
          (await wallet.getSupportedSignatureSchemes(keyId))[0];

      JwsHeader jwsHeader = JwsHeader(
          typ: DidcommMessageTyp.signed.value,
          alg: scheme.alg!,
          crv: scheme.crv!);

      // TODO: improve this one here
      String data = _base64Payload != null
          ? utf8.decode(base64Decode(_base64Payload!))
          : jsonEncode(payload.toJson());

      String encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(jwsHeader.toJson()))));

      String encodedPayload =
          removePaddingFromBase64(base64UrlEncode(utf8.encode(data)));

      Uint8List signingInput = ascii.encode('$encodedHeader.$encodedPayload');
      Uint8List jws = await wallet.sign(signingInput, keyId: keyId);
      final publicKey = await wallet.getPublicKey(keyId);
      final didDoc = DidKey.generateDocument(publicKey);

      final sig = removePaddingFromBase64(base64UrlEncode(jws));
      final result = '$encodedHeader..$sig';

      signatures!.add(SignatureObject(
          signature: result.split('..').last,
          protected: jwsHeader.toJson(),

          /// TIMTAM added kid APR 01 2025
          header: {'kid': didDoc.resolveKeyIds().keyAgreement[0].id}));
    }

    return;
  }

  Future<bool> verify(Jwk jwk) async {
    if (jwk.doc['crv'] == null) {
      throw Exception('Jwk without crv parameter');
    }

    if (signatures == null || signatures!.isEmpty) {
      throw Exception('Nothing to verify');
    }

    bool valid = true;

    for (var s in signatures!) {
      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(s.protected))));

      var encodedPayload = _base64Payload ??
          removePaddingFromBase64(
              base64UrlEncode(utf8.encode(payload.toString())));

      SignatureScheme sigScheme =
          SignatureScheme.fromString(s.protected!['alg']);

      final verifier = await DidVerifier.create(
        algorithm: sigScheme,
        issuerDid: jwk.toJson()['kid']!.split('#').first,
      );

      valid = verifier.verify(ascii.encode('$encodedHeader.$encodedPayload'),
          base64Decode(addPaddingToBase64(s.signature)));

      if (!valid) {
        throw Exception('A Signature is wrong');
      }
    }

    return valid;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
