import '../../../util/json_util.dart';

abstract interface class _IssuerInterface {
  Uri? get id;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({'id': id?.toString()});
}

/// Represents a Mutable Issuer for verifiable credentials following W3C standards.
///
/// An issuer is an entity that creates and digitally signs verifiable credentials, asserting claims about a subject.
///
/// Example:
/// ```dart
/// final isuer = MutableIssuer(
///   id: Uri.parse('did:example:12345'),
/// );
/// ```
class MutableIssuer extends _IssuerInterface {
  /// the URL of  unique identifier for the issuer object
  Uri? id;

  /// Creates a [MutableIssuer]
  ///
  /// The [id] - is id for issuer object.
  MutableIssuer({this.id});

  /// Creates a [MutableIssuer] from JSON data.
  ///
  /// The [json] must contain 'id'
  factory MutableIssuer.fromJson(dynamic json) {
    final id = getUri(json, 'id');
    return MutableIssuer(id: id);
  }

  /// Creates a [MutableIssuer] from a URI.
  ///
  /// This factory constructor is a shorthand for [MutableIssuer.fromJson]
  /// when the input is expected to be a URI or a value that can be parsed as a URI.
  ///
  /// Example:
  /// ```dart
  /// final issuer = MutableIssuer.uri("did:example:12345");
  /// ```
  factory MutableIssuer.uri(dynamic json) => MutableIssuer.fromJson(json);
}

/// Represents a Issuer for verifiable credentials following W3C standards.
///
/// An issuer is an entity that creates and digitally signs verifiable credentials, asserting claims about a subject.
///
/// Example:
/// ```dart
/// final issuer = Issuer(
///   id: Uri.parse('did:example:12345'),
/// );
/// ```
class Issuer extends MutableIssuer {
  final Uri _id;

  @override
  Uri get id => _id;

  /// Creates a [Issuer]
  ///
  /// The [id] - is id for issuer object.
  Issuer({required Uri id}) : _id = id;

  /// Creates a [Issuer] from JSON data.
  ///
  /// The [json] must contain 'id'
  factory Issuer.fromJson(dynamic json) {
    final id = getMandatoryUri(json, 'id');
    return Issuer(id: id);
  }

  /// Creates a [Issuer] from a URI.
  ///
  /// This factory constructor is a shorthand for [Issuer.fromJson]
  /// when the input is expected to be a URI or a value that can be parsed as a URI.
  ///
  /// Example:
  /// ```dart
  /// final issuer = Issuer.uri("did:example:12345");
  /// ```
  factory Issuer.uri(dynamic json) => Issuer.fromJson(json);
}
