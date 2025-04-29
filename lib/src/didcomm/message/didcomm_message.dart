import 'dart:convert';

import 'package:ssi/src/didcomm/message/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_signed_message.dart';
import 'package:ssi/src/didcomm/message/jwe_header.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';

abstract class DidcommMessage implements JsonObject {
  factory DidcommMessage.fromDecrypted(
      dynamic json, JweHeader protectedHeader) {
    if (json.containsKey('id')) {
      final decryptedMessage = DidcommPlaintextMessage.fromJson(json);

      if (!protectedHeader.isAuthCrypt()) {
        return decryptedMessage;
      }

      if (decryptedMessage.from == null) {
        throw Exception(
            'From value in plaintext message is required if authcrypt is used');
      }

      if (decryptedMessage.from != protectedHeader.skid?.split('#').first) {
        throw Exception(
            'From value of plaintext Message do not match skid of encrypted message');
      }

      return decryptedMessage;
    }

    if (json.containsKey('ciphertext')) {
      return DidcommEncryptedMessage.fromJson(json);
    }

    if (json.containsKey('signatures')) {
      return DidcommSignedMessage.fromJson(json);
    }

    if (json.containsKey('payload')) {
      return DidcommPlaintextMessage.fromJson(
          decodeBase64ToString(json['payload']));
    }
    throw Exception('Unknown message type');
  }
}
