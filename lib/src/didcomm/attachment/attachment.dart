import 'dart:convert';

import 'package:ssi/src/didcomm/attachment/attachment_data.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';

class Attachment implements JsonObject {
  String? id;
  String? description;
  String? filename;
  String? mediaType;
  String? format;
  DateTime? lastmodTime;
  int? byteCount;
  late AttachmentData data;

  Attachment(
      {required this.data,
      this.id,
      this.description,
      this.filename,
      this.mediaType,
      this.format,
      this.lastmodTime,
      this.byteCount});

  Attachment.fromJson(dynamic jsonData) {
    Map<String, dynamic> decoded = credentialToMap(jsonData);
    if (decoded.containsKey('data')) {
      data = AttachmentData.fromJson(decoded['data']);
    } else {
      throw FormatException('an Attachment must contain a data property');
    }

    id = decoded['id'];
    description = decoded['description'];
    filename = decoded['filename'];
    mediaType = decoded['media_type'];
    format = decoded['format'];
    if (decoded.containsKey('lastmod_time') &&
        decoded['lastmod_time'] != null) {
      lastmodTime = DateTime.fromMillisecondsSinceEpoch(
          decoded['lastmod_time'] * 1000,
          isUtc: true);
    }
    byteCount = decoded['byte_count'];
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonData = {};
    jsonData['data'] = data.toJson();
    if (id != null) jsonData['id'] = id;
    if (description != null) jsonData['description'] = description;
    if (filename != null) jsonData['filename'] = filename;
    if (mediaType != null) jsonData['media_type'] = mediaType;
    if (format != null) jsonData['format'] = format;
    if (lastmodTime != null) {
      jsonData['lastmod_time'] = lastmodTime!.millisecondsSinceEpoch ~/ 1000;
    }
    if (byteCount != null) jsonData['byte_count'] = byteCount;
    return jsonData;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
