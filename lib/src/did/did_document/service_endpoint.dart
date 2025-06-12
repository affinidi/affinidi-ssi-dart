import 'dart:convert';

import '../../types.dart';
import '../../util/json_util.dart';
import 'service_endpoint_value.dart';

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
      accept: (json['accept'] as List?)?.cast<String>() ?? <String>[],
      routingKeys: (json['routingKeys'] as List?)?.cast<String>() ?? <String>[],
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

  /// The service endpoint value (can be string, map, or set).
  late ServiceEndpointValue serviceEndpoint;

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
      throw const FormatException('type property is needed in serviceEndpoint');
    }
    if (se.containsKey('serviceEndpoint')) {
      serviceEndpoint =
          ServiceEndpointValueParser.fromJson(se['serviceEndpoint']);
    } else {
      throw const FormatException(
          'serviceEndpoint property is needed in serviceEndpoint');
    }
  }

  /// Helper method to extract DIDComm endpoints if the service is DIDComm-compatible.
  List<DIDCommServiceEndpoint>? get didCommEndpoints {
    final value = serviceEndpoint;
    if (value is MapEndpoint && value.data.containsKey('uri')) {
      try {
        return [DIDCommServiceEndpoint.fromJson(value.data)];
      } catch (_) {
        return null;
      }
    }
    if (value is SetEndpoint) {
      final endpoints = <DIDCommServiceEndpoint>[];
      for (final endpoint in value.endpoints) {
        if (endpoint is MapEndpoint && endpoint.data.containsKey('uri')) {
          try {
            endpoints.add(DIDCommServiceEndpoint.fromJson(endpoint.data));
          } catch (_) {
            // Skip non-DIDComm endpoints
          }
        }
      }
      return endpoints.isEmpty ? null : endpoints;
    }
    return null;
  }

  /// Factory constructor for creating a DIDComm service endpoint.
  factory ServiceEndpoint.didComm({
    required String id,
    required List<DIDCommServiceEndpoint> endpoints,
  }) {
    return ServiceEndpoint(
      id: id,
      type: 'DIDCommMessaging',
      serviceEndpoint: endpoints.length == 1
          ? MapEndpoint(endpoints.first.toJson())
          : SetEndpoint(
              endpoints.map((e) => MapEndpoint(e.toJson())).toList(),
            ),
    );
  }

  /// Converts this service endpoint to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final dynamic jsonValue;
    switch (serviceEndpoint) {
      case StringEndpoint(:final url):
        jsonValue = url;
      case MapEndpoint(:final data):
        jsonValue = data;
      case SetEndpoint(:final endpoints):
        jsonValue = endpoints.map((e) {
          switch (e) {
            case StringEndpoint(:final url):
              return url;
            case MapEndpoint(:final data):
              return data;
            case SetEndpoint():
              throw StateError('Nested sets are not supported');
          }
        }).toList();
    }

    return {
      'id': id,
      'type': type,
      'serviceEndpoint': jsonValue,
    };
  }

  /// Returns the JSON string representation of the service endpoint.
  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
