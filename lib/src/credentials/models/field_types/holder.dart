import '../../../util/json_util.dart';

abstract interface class _HolderInterface {
  Uri? get id;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({'id': id?.toString()});
}

/// Represents a Mutable Holder for verifiable credentials following W3C standards.
///
/// A Holder is an entity possessing and capable of presenting verifiable digital credentials.
///
/// Example:
/// ```dart
/// final holder = MutableHolder(
///   id: Uri.parse('did:example:12345'),
/// );
/// ```
class MutableHolder extends _HolderInterface {
  /// the URL of  unique identifier for the holder object
  Uri? id;

  /// Creates a [MutableHolder]
  ///
  /// The [id] - is id for holder object.
  MutableHolder({this.id});

  /// Creates a [MutableHolder] from JSON data.
  ///
  /// The [json] must contain 'id'
  factory MutableHolder.fromJson(dynamic json) {
    final id = getUri(json, 'id');
    return MutableHolder(id: id);
  }

  /// Creates a [MutableHolder] from a URI.
  ///
  /// This factory constructor is a shorthand for [MutableHolder.fromJson]
  /// when the input is expected to be a URI or a value that can be parsed as a URI.
  ///
  /// Example:
  /// ```dart
  /// final holder = MutableHolder.uri("did:example:12345");
  /// ```
  factory MutableHolder.uri(dynamic json) => MutableHolder.fromJson(json);
}

/// Represents a Holder for verifiable credentials following W3C standards.
///
/// A Holder is an entity possessing and capable of presenting verifiable digital credentials.
///
/// Example:
/// ```dart
/// final holder = Holder(
///   id: Uri.parse('did:example:12345'),
/// );
/// ```
class Holder extends _HolderInterface {
  final Uri _id;

  @override
  Uri get id => _id;

  /// Creates a [Holder]
  ///
  /// The [id] - is id for holder object.
  Holder({required Uri id}) : _id = id;

  /// Creates a [Holder] from JSON data.
  ///
  /// The [json] must contain 'id'
  factory Holder.fromJson(dynamic json) {
    final id = getMandatoryUri(json, 'id');
    return Holder(id: id);
  }

  /// Creates a [Holder] from a URI.
  ///
  /// This factory constructor is a shorthand for [Holder.fromJson]
  /// when the input is expected to be a URI or a value that can be parsed as a URI.
  ///
  /// Example:
  /// ```dart
  /// final holder = Holder.uri("did:example:12345");
  /// ```
  factory Holder.uri(dynamic json) => Holder.fromJson(json);
}
