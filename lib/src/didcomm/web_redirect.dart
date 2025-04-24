import 'dart:convert';

import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/ssi.dart';

class WebRedirect implements JsonObject {
  late String redirectUrl;
  late AcknowledgeStatus status;

  WebRedirect({required this.redirectUrl, required this.status});

  WebRedirect.fromJson(dynamic jsonObject) {
    Map<String, dynamic> json = credentialToMap(jsonObject);
    if (json.containsKey('status')) {
      String s = json['status'];
      switch (s) {
        case 'FAIL':
          status = AcknowledgeStatus.fail;
          break;
        case 'OK':
          status = AcknowledgeStatus.ok;
          break;
        case 'PENDING':
          status = AcknowledgeStatus.pending;
          break;
        default:
          throw Exception('Unknown Status');
      }
    } else {
      throw Exception('status attribute is needed');
    }

    if (json.containsKey('redirectUrl')) {
      redirectUrl = json['redirectUrl'];
    } else {
      throw Exception('redirectUrl is needed');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'status': status.value, 'redirectUrl': redirectUrl};
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
