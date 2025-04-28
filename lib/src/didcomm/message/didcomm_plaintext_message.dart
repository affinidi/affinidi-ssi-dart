import 'dart:convert';

import 'package:ssi/src/did/did_signer.dart';
import 'package:ssi/src/didcomm/attachment/attachment.dart';
import 'package:ssi/src/didcomm/message/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/didcomm_jwt.dart';
import 'package:ssi/src/didcomm/message/didcomm_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_signed_message.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/didcomm/web_redirect.dart';
import 'package:ssi/src/wallet/wallet.dart';
import 'package:uuid/uuid.dart';

import '../../types.dart';
import '../types.dart';

class DidcommPlaintextMessage implements JsonObject, DidcommMessage {
  List<dynamic>? to;
  String? from;
  late String id;
  late String type;
  DidcommMessageTyp? typ;
  String? threadId;
  String? parentThreadId;
  DateTime? createdTime;
  DateTime? expiresTime;
  late Map<String, dynamic> body;
  FromPriorJWT? fromPrior;
  List<Attachment>? attachments;
  Map<String, dynamic>? additionalHeaders;
  List<String>? pleaseAck;
  List<String>? ack;
  String? replyUrl;
  List<String>? replyTo;
  WebRedirect? webRedirect;
  ReturnRouteValue? returnRoute;

  DidcommPlaintextMessage(
      {required this.id,
      required this.type,
      required this.body,
      this.replyUrl,
      this.replyTo,
      this.typ,
      String? threadId,
      this.parentThreadId,
      this.createdTime,
      this.expiresTime,
      this.to,
      this.from,
      this.fromPrior,
      this.attachments,
      bool pleaseAck = false,
      this.ack,
      this.webRedirect,
      this.additionalHeaders,
      this.returnRoute}) {
    if (pleaseAck) this.pleaseAck = [id];
    this.threadId = threadId ?? id;
  }

  factory DidcommPlaintextMessage.to(String to,
      {required String type, required Map<String, dynamic> body}) {
    return DidcommPlaintextMessage(id: Uuid().v4(), type: type, body: body);
  }

  Future<DidcommEncryptedMessage> encrypt(
      {KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.ecdh1PU,
      EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.a256cbc,
      required Wallet wallet,
      required String keyId,
      required List<Map<String, dynamic>> recipientPublicKeyJwks}) {
    return DidcommEncryptedMessage.fromPlaintext(
        keyWrapAlgorithm: keyWrapAlgorithm,
        encryptionAlgorithm: encryptionAlgorithm,
        wallet: wallet,
        keyId: keyId,
        recipientPublicKeyJwks: recipientPublicKeyJwks,
        message: this);
  }

  Future<DidcommSignedMessage> sign(DidSigner signer) {
    return DidcommSignedMessage.fromPlaintext(this, signer: signer);
  }

  DidcommPlaintextMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    id = decoded['id']!;
    type = decoded['type']!;
    replyUrl = decoded['reply_url'];
    if (decoded.containsKey('reply_to') && decoded['reply_to'] != null) {
      replyTo = decoded['reply_to'].cast<String>();
    }
    if (decoded.containsKey('body')) {
      Map tmp = decoded['body'];
      if (tmp.isEmpty) {
        body = {};
      } else {
        body = tmp.cast<String, dynamic>();
      }
    } else {
      body = {};
      if (type != 'https://didcomm.org/empty/1.0') {
        throw Exception('Empty Body only allowed in Empty Message');
      }
    }
    from = decoded['from'];
    to = decoded['to'];
    threadId = decoded['thid'];
    parentThreadId = decoded['pthid'];
    if (decoded.containsKey('typ')) {
      String typTmp = decoded['typ'];
      switch (typTmp) {
        case 'application/didcomm-plain+json':
          typ = DidcommMessageTyp.plain;
          break;
        case 'application/didcomm-signed+json':
          typ = DidcommMessageTyp.signed;
          break;
        case 'application/didcomm-encrypted+json':
          typ = DidcommMessageTyp.encrypted;
          break;
        default:
          throw Exception('Unknown typ field $typTmp');
      }
    }
    var tmp = decoded['created_time'];
    if (tmp != null) {
      createdTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);
    }
    tmp = decoded['expires_time'];
    if (tmp != null) {
      expiresTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);
    }

    if (decoded.containsKey('from_prior')) {
      fromPrior = FromPriorJWT.fromCompactSerialization(decoded['from_prior']);
      if (fromPrior != null && from != null) {
        if (from != fromPrior!.sub) {
          throw Exception('from value must match from_prior.sub');
        }
      }
    }

    if (decoded.containsKey('attachments')) {
      List tmp = decoded['attachments'];
      if (tmp.isNotEmpty) {
        attachments = [];
        for (var a in tmp) {
          attachments!.add(Attachment.fromJson(a));
        }
      }
    }
    if (decoded.containsKey('please_ack') && decoded['please_ack'] != null) {
      pleaseAck = decoded['please_ack'].cast<String>();
    }
    if (decoded.containsKey('ack') && decoded['ack'] != null) {
      ack = decoded['ack'].cast<String>();
    }

    if (decoded.containsKey('web_redirect') &&
        decoded['web_redirect'] != null) {
      webRedirect = WebRedirect.fromJson(decoded['web_redirect']);
    }

    if (decoded.containsKey('return_route')) {
      var tmp = decoded['return_route'];
      switch (tmp) {
        case 'all':
          returnRoute = ReturnRouteValue.all;
          break;
        case 'none':
          returnRoute = ReturnRouteValue.none;
          break;
        case 'thread':
          returnRoute = ReturnRouteValue.thread;
          break;
      }
    }
    decoded.remove('to');
    decoded.remove('from');
    decoded.remove('id');
    decoded.remove('type');
    decoded.remove('typ');
    decoded.remove('thid');
    decoded.remove('pthid');
    decoded.remove('created_time');
    decoded.remove('expires_time');
    decoded.remove('body');
    decoded.remove('from_prior');
    decoded.remove('attachments');
    decoded.remove('ack');
    decoded.remove('please_ack');
    decoded.remove('reply_to');
    decoded.remove('reply_url');
    decoded.remove('web_redirect');
    decoded.remove('return_route');
    if (decoded.isNotEmpty) additionalHeaders = decoded;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> message = {};
    message['id'] = id;
    if (typ != null) message['typ'] = typ!.value;
    message['type'] = type;
    if (from != null) message['from'] = from;
    if (to != null) message['to'] = to;
    if (threadId != null) message['thid'] = threadId;
    if (parentThreadId != null) message['pthid'] = parentThreadId;
    if (createdTime != null) {
      message['created_time'] = createdTime!.millisecondsSinceEpoch ~/ 1000;
    }
    if (expiresTime != null) {
      message['expires_time'] = expiresTime!.millisecondsSinceEpoch ~/ 1000;
    }

    if (pleaseAck != null) message['please_ack'] = pleaseAck;
    if (ack != null) message['ack'] = ack;
    if (webRedirect != null) message['web_redirect'] = webRedirect!.toJson();
    if (returnRoute != null) message['return_route'] = returnRoute!.value;
    if (additionalHeaders != null) message.addAll(additionalHeaders!);
    message['body'] = body;

    //TODO: from_prior header

    if (attachments != null) {
      List<Map<String, dynamic>> tmp = [];
      for (var a in attachments!) {
        tmp.add(a.toJson());
      }
      message['attachments'] = tmp;
    }

    if (replyUrl != null) message['reply_url'] = replyUrl;
    if (replyTo != null) message['reply_to'] = replyTo;

    return message;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
