import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';

class DidCommMessageRecipientHeader implements JsonObject {
  final String kid;

  DidCommMessageRecipientHeader({required this.kid});

  @override
  Map<String, dynamic> toJson() {
    return {'kid': kid};
  }

  factory DidCommMessageRecipientHeader.fromJson(dynamic json) {
    return DidCommMessageRecipientHeader(kid: json['kid']);
  }
}

class DidCommMessageRecipient implements JsonObject {
  final DidCommMessageRecipientHeader header;
  final Uint8List encryptedKey;

  DidCommMessageRecipient({required this.header, required this.encryptedKey});

  @override
  Map<String, dynamic> toJson() {
    return {
      'header': header.toJson(),
      'encrypted_key': removePaddingFromBase64(base64UrlEncode(encryptedKey)),
    };
  }

  factory DidCommMessageRecipient.fromJson(Map<String, dynamic> json) {
    return DidCommMessageRecipient(
        header: DidCommMessageRecipientHeader.fromJson(json['header']),
        encryptedKey: base64Decode(addPaddingToBase64(json['encrypted_key'])));
  }
}
