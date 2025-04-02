import 'dart:convert';

import 'package:json_path/json_path.dart';
import 'package:uuid/uuid.dart';

import '../util/types.dart';
import '../util/utils.dart';

class PresentationSubmission implements JsonObject {
  late String id;
  late String presentationDefinitionId;
  late List<InputDescriptorMappingObject> descriptorMap;
  Map<String, dynamic>? _originalDoc;

  PresentationSubmission(
      {String? id,
      required this.presentationDefinitionId,
      required this.descriptorMap})
      : id = id ?? Uuid().v4();

  PresentationSubmission.fromJson(dynamic jsonObject) {
    Map<String, dynamic> submission = credentialToMap(jsonObject);
    if (submission.containsKey('id')) {
      id = submission['id'];
    } else {
      throw FormatException('Id Property is needed in presentation submission');
    }

    if (submission.containsKey('definition_id')) {
      presentationDefinitionId = submission['definition_id'];
    } else {
      throw FormatException(
          'Definition id is needed in presentation submission');
    }

    if (submission.containsKey('descriptor_map')) {
      List tmp = submission['descriptor_map'];
      descriptorMap = [];
      if (tmp.isNotEmpty) {
        for (var d in tmp) {
          descriptorMap.add(InputDescriptorMappingObject.fromJson(d));
        }
      }
    } else {
      throw FormatException(
          'descriptor_map property is needed in presentation submission');
    }

    _originalDoc = submission;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;

    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['definition_id'] = presentationDefinitionId;
    jsonObject['descriptor_map'] =
        descriptorMap.map((d) => d.toJson()).toList();

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class InputDescriptorMappingObject implements JsonObject {
  late String id;
  late String format;
  late JsonPath path;
  Map<String, dynamic>? _originalDoc;

  InputDescriptorMappingObject(
      {required this.id, required this.format, required this.path});

  InputDescriptorMappingObject.fromJson(dynamic jsonObject) {
    Map<String, dynamic> descriptor = credentialToMap(jsonObject);
    if (descriptor.containsKey('id')) {
      id = descriptor['id'];
    } else {
      throw Exception('Id property is needed in descriptor-Map Object');
    }

    if (descriptor.containsKey('format')) {
      format = descriptor['format'];
    } else {
      throw Exception('Format property is needed in descriptor-map object');
    }

    if (descriptor.containsKey('path')) {
      path = JsonPath(descriptor['path']);
    } else {
      throw Exception('path property is needed in descriptor-map object');
    }
    _originalDoc = descriptor;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;

    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['format'] = format;
    jsonObject['path'] = path.toString();
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
