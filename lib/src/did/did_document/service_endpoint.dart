import 'dart:convert';

import '../../types.dart';
import '../../util/json_util.dart';

/// Represents a DIDComm service endpoint.
class DIDCommServiceEndpoint {
  /// The list of accepted media types.
  final List<String> accept;

  /// The list of routing keys.
  final List<String> routingKeys;

  /// The URI of the service endpoint.
  final String uri;

  /// Creates a [DIDCommServiceEndpoint] instance.
  DIDCommServiceEndpoint({
    required this.accept,
    required this.routingKeys,
    required this.uri,
  });

  /// Creates a [DIDCommServiceEndpoint] from JSON input.
  factory DIDCommServiceEndpoint.fromJson(Map<String, dynamic> json) {
    return DIDCommServiceEndpoint(
      accept: (json['accept'] as List).cast<String>(),
      routingKeys: (json['routingKeys'] as List).cast<String>(),
      uri: json['uri'] as String,
    );
  }

  /// Converts this service endpoint to a JSON-serializable map.
  Map<String, dynamic> toJson() => {
        'accept': accept,
        'routingKeys': routingKeys,
        'uri': uri,
      };
}

/// Represents a service endpoint in a DID Document.
class ServiceEndpoint implements JsonObject {
  /// The identifier of the service endpoint.
  late String id;

  /// The type of the service endpoint.
  late String type;

  /// The list of DIDComm service endpoints.
  late List<DIDCommServiceEndpoint> serviceEndpoint;
  String? _originalStringEndpoint;
  Map<String, dynamic>? _originalMapEndpoint;

  /// Creates a [ServiceEndpoint] instance.
  ServiceEndpoint({
    required this.id,
    required this.type,
    required this.serviceEndpoint,
  });

  /// Creates a [ServiceEndpoint] from JSON input.
  ServiceEndpoint.fromJson(dynamic jsonObject) {
    final se = jsonToMap(jsonObject);
    if (se.containsKey('id')) {
      id = se['id'];
    } else {
      throw const FormatException('id property is needed in serviceEndpoint');
    }
    if (se.containsKey('type')) {
      type = se['type'];
    } else {
      throw const FormatException(
          'format property is needed in serviceEndpoint');
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
        throw const FormatException(
            'serviceEndpoint must be a list, map, or string');
      }
    } else {
      throw const FormatException(
          'serviceEndpoint property is needed in serviceEndpoint');
    }
  }

  /// Converts this service endpoint to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    var jsonObject = <String, dynamic>{};
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

  /// Returns the JSON string representation of the service endpoint.
  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
