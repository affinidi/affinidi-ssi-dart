import 'dart:convert';

import '../../types.dart';
import '../../util/json_util.dart';
import 'service_endpoint_value.dart';
import 'service_type.dart';

/// Represents a service endpoint in a DID Document.
/// Following https://www.w3.org/TR/did-1.0/#services
class ServiceEndpoint implements JsonObject {
  // TODO: This class actually represents a `Service`, not the underlying endpoint. Rename it

  /// The identifier of the service endpoint.
  late String id;

  // TODO: In the spec, ID can be optional

  /// The type of the service endpoint.
  /// Can be a string or a set of strings as per https://www.w3.org/TR/did-1.0/#services
  late ServiceType type;

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

    switch (se['type']) {
      case String strType:
        type = strType;

      case [String strType]:
        type = strType;

      default:
        throw const FormatException('invalid type property in serviceEndpoint');
    }

    if (se.containsKey('serviceEndpoint')) {
      serviceEndpoint =
          ServiceEndpointValueParser.fromJson(se['serviceEndpoint']);
    } else {
      throw const FormatException(
          'serviceEndpoint property is needed in serviceEndpoint');
    }
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
      'type': type.toJson(),
      'serviceEndpoint': jsonValue,
    };
  }

  /// Returns the JSON string representation of the service endpoint.
  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
