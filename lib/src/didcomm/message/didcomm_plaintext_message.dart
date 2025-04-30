import 'dart:convert';
import 'package:uuid/uuid.dart';

import 'package:ssi/src/did/did_signer.dart';
import 'package:ssi/src/didcomm/attachment/attachment.dart';
import 'package:ssi/src/didcomm/message/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_signed_message.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/didcomm/web_redirect.dart';
import 'package:ssi/src/types.dart';
import 'package:ssi/src/wallet/wallet.dart';

const typeMap = {
  'application/didcomm-plain+json': DidcommMessageTyp.plain,
  'application/didcomm-signed+json': DidcommMessageTyp.signed,
  'application/didcomm-encrypted+json': DidcommMessageTyp.encrypted,
};

const returnRouteMap = {
  'all': ReturnRouteValue.all,
  'none': ReturnRouteValue.none,
  'thread': ReturnRouteValue.thread,
};

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

  factory DidcommPlaintextMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    if (!decoded.containsKey('body') && _isEmptyMessageType(decoded['type'])) {
      throw Exception('Empty Body only allowed in Empty Message');
    }

    if (decoded.containsKey('typ') && typeMap[decoded['typ']] == null) {
      throw Exception('Unknown typ field ${decoded['typ']}');
    }

    Map<String, dynamic> body = {};
    if (decoded.containsKey('body')) {
      Map tmp = decoded['body'];
      body = tmp.isEmpty ? {} : tmp.cast<String, dynamic>();
    }

    List<Attachment>? attachments;
    if (decoded.containsKey('attachments') && decoded['attachments'] is List) {
      List decodedAttachments = decoded['attachments'];
      attachments = [];
      for (var a in decodedAttachments) {
        attachments.add(Attachment.fromJson(a));
      }
    }

    return DidcommPlaintextMessage(
      id: decoded['id'],
      type: decoded['type'],
      body: body,
      from: decoded['from'],
      to: decoded['to'],
      threadId: decoded['thid'],
      parentThreadId: decoded['pthid'],
      typ: typeMap[decoded['typ']],
      replyUrl: decoded['reply_url'],
      replyTo: decoded['reply_to']?.cast<String>(),
      pleaseAck: decoded['please_ack']?.cast<bool>() ?? false,
      ack: decoded['ack']?.cast<String>(),
      webRedirect: decoded['web_redirect'] != null
          ? WebRedirect.fromJson(decoded['web_redirect'])
          : null,
      returnRoute: decoded['return_route'] != null
          ? returnRouteMap[decoded['return_route']]
          : null,
      createdTime: _convertToDateTimeIfNotNull(decoded['created_time']),
      expiresTime: _convertToDateTimeIfNotNull(decoded['expires_time']),
      additionalHeaders: decoded['additionalHeaders'],
      attachments: attachments,
    );
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

  static DateTime? _convertToDateTimeIfNotNull(int? ms) {
    if (ms == null) return null;
    return DateTime.fromMillisecondsSinceEpoch(ms * 1000, isUtc: true);
  }

  static bool _isEmptyMessageType(String type) {
    return type == 'https://didcomm.org/empty/1.0';
  }
}
