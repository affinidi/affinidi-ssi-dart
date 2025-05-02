import 'dart:convert';

import '../../types.dart';
import '../../util/json_util.dart';

class DIDCommServiceEndpoint {
  final List<String> accept;
  final List<String> routingKeys;
  final String uri;

  DIDCommServiceEndpoint({
    required this.accept,
    required this.routingKeys,
    required this.uri,
  });

  factory DIDCommServiceEndpoint.fromJson(Map<String, dynamic> json) {
    return DIDCommServiceEndpoint(
      accept: (json['accept'] as List).cast<String>(),
      routingKeys: (json['routingKeys'] as List).cast<String>(),
      uri: json['uri'] as String,
    );
  }

  Map<String, dynamic> toJson() => {
        'accept': accept,
        'routingKeys': routingKeys,
        'uri': uri,
      };
}

class ServiceEndpoint implements JsonObject {
  late String id;
  late String type;
  late List<DIDCommServiceEndpoint> serviceEndpoint;
  String? _originalStringEndpoint;
  Map<String, dynamic>? _originalMapEndpoint;

  ServiceEndpoint({
    required this.id,
    required this.type,
    required this.serviceEndpoint,
  });

  ServiceEndpoint.fromJson(dynamic jsonObject) {
    final se = jsonToMap(jsonObject);
    if (se.containsKey('id')) {
      id = se['id'];
    } else {
      throw FormatException('id property is needed in serviceEndpoint');
    }
    if (se.containsKey('type')) {
      type = se['type'];
    } else {
      throw FormatException('format property is needed in serviceEndpoint');
    }
    if (se.containsKey('serviceEndpoint')) {
      final endpoint = se['serviceEndpoint'];
      if (endpoint is List) {
        serviceEndpoint = endpoint
            .map((e) =>
                DIDCommServiceEndpoint.fromJson(Map<String, dynamic>.from(e)))
            .toList();
      } else if (endpoint is Map<String, dynamic>) {
        _originalMapEndpoint = Map<String, dynamic>.from(endpoint);
        serviceEndpoint = [
          DIDCommServiceEndpoint.fromJson(_originalMapEndpoint!)
        ];
      } else if (endpoint is String) {
        _originalStringEndpoint = endpoint;
        serviceEndpoint = [
          DIDCommServiceEndpoint(
              uri: endpoint, accept: <String>[], routingKeys: <String>[])
        ];
      } else {
        throw FormatException('serviceEndpoint must be a list, map, or string');
      }
    } else {
      throw FormatException(
          'serviceEndpoint property is needed in serviceEndpoint');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['type'] = type;

    if (_originalStringEndpoint != null) {
      jsonObject['serviceEndpoint'] = _originalStringEndpoint;
    } else if (_originalMapEndpoint != null) {
      jsonObject['serviceEndpoint'] = _originalMapEndpoint;
    } else {
      jsonObject['serviceEndpoint'] =
          serviceEndpoint.map((e) => e.toJson()).toList();
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
