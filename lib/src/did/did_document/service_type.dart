/// Represents the type of a service in a DID Document.
/// According to https://www.w3.org/TR/did-1.0/#services, the type property
/// can be a string or a set of strings.
sealed class ServiceType {
  const ServiceType();

  /// Creates a [ServiceType] from a JSON value.
  factory ServiceType.fromJson(dynamic json) {
    if (json is String) {
      return StringServiceType(json);
    } else if (json is List) {
      return SetServiceType(List<String>.from(json));
    } else {
      throw FormatException(
          'Service type must be a string or a list of strings, got: ${json.runtimeType}');
    }
  }

  /// Converts this service type to a JSON-serializable value.
  dynamic toJson();
}

/// A service type represented as a single string.
class StringServiceType extends ServiceType {
  /// The type string value.
  final String value;

  /// Creates a [StringServiceType] with the given value.
  const StringServiceType(this.value);

  @override
  dynamic toJson() => value;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is StringServiceType && value == other.value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value;
}

/// A service type represented as a set of strings.
class SetServiceType extends ServiceType {
  /// The list of type strings.
  final List<String> values;

  /// Creates a [SetServiceType] with the given values.
  const SetServiceType(this.values);

  @override
  dynamic toJson() => values;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! SetServiceType) return false;
    return Set<String>.from(values).containsAll(other.values) &&
        Set<String>.from(other.values).containsAll(values);
  }

  @override
  int get hashCode => Set<String>.from(values).hashCode;

  @override
  String toString() => values.toString();
}
