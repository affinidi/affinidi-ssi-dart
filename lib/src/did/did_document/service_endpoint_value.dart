import '../../util/json_util.dart';

/// Represents the value of a service endpoint in a DID Document.
///
/// According to W3C DID specification, a serviceEndpoint can be:
/// - A single string (URL)
/// - A single map (arbitrary structure)
/// - A set composed of one or more strings and/or maps
sealed class ServiceEndpointValue {
  const ServiceEndpointValue();
}

/// Represents a service endpoint that is a single URL string.
class StringEndpoint extends ServiceEndpointValue {
  /// The URL of the service endpoint.
  final String url;

  /// Creates a string endpoint.
  const StringEndpoint(this.url);
}

/// Represents a service endpoint that is a map of arbitrary data.
class MapEndpoint extends ServiceEndpointValue {
  /// The map data of the service endpoint.
  final Map<String, dynamic> data;

  /// Creates a map endpoint.
  const MapEndpoint(this.data);
}

/// Represents a service endpoint that is a set of endpoints.
class SetEndpoint extends ServiceEndpointValue {
  /// The list of service endpoints.
  final List<ServiceEndpointValue> endpoints;

  /// Creates a set endpoint.
  const SetEndpoint(this.endpoints);
}

/// Extension to handle JSON parsing for ServiceEndpointValue.
extension ServiceEndpointValueParser on ServiceEndpointValue {
  /// Creates a ServiceEndpointValue from JSON data.
  /// The input should be already parsed from JSON string.
  static ServiceEndpointValue fromJson(dynamic json) {
    if (json is String) {
      return StringEndpoint(json);
    }
    if (json is Map) {
      return MapEndpoint(jsonToMap(json));
    }
    if (json is List) {
      return SetEndpoint(
        json.map(ServiceEndpointValueParser.fromJson).toList(),
      );
    }
    throw const FormatException(
      'serviceEndpoint must be a string, map, or list',
    );
  }
}
