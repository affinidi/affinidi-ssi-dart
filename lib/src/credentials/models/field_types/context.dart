import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';

/// Base interface for JSON-LD `@context`.
///
/// This interface provides access to the stored context and the
/// first URI, along with serialization to JSON.
abstract interface class _JsonLdContextInterface {
  /// Returns the stored JSON-LD context.
  ///
  /// Can be a [String] URI, a [Map] of term definitions, or a [List] of
  /// URIs and/or term maps.
  Object get context;

  /// Returns the first URI in the context, if any.
  ///
  /// Searches the stored [context] for the first string URI.
  /// Returns `null` if no string URI is found.
  Uri? get firstUri;

  /// Serializes the stored context back to a JSON-compatible object.
  ///
  /// Returns the original [context] value.
  Object toJson() => context;
}

/// Represents an immutable JSON-LD `@context`.
///
/// Stores the context and provides access to the first URI as well as JSON
/// serialization. Throws an exception if the first element of a list is not
/// a string URI to comply with VC 1.1 specification.
///
/// Example:
/// ```dart
/// final context = JsonLdContext.fromJson(
///   ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://schema.org/"}],
/// );
/// print(context.firstUri); // https://www.w3.org/ns/credentials/v2
/// ```
class JsonLdContext extends _JsonLdContextInterface {
  /// The stored JSON-LD context.
  @override
  final Object context;

  /// Private constructor to enforce creation via `fromJson`.
  JsonLdContext._(this.context);

  /// Returns the first string URI in the context.
  ///
  /// If [context] is a string, parses and returns it as a [Uri].
  /// If [context] is a list, returns the first element as a [Uri] (VC-compliant).
  /// Returns `null` if no string URI is present.
  @override
  Uri? get firstUri {
    if (context is String) return Uri.tryParse(context as String);

    if (context is List) {
      final list = context as List<dynamic>;
      if (list.isNotEmpty && list.first is String) {
        return Uri.tryParse(list.first as String);
      }
    }

    return null;
  }

  /// Creates an immutable JSON-LD context from a JSON object.
  ///
  /// Accepts a [String] URI, a [Map] of term definitions, or a [List] of URIs
  /// and/or term maps.
  ///
  /// Throws [SsiException] if [json] is `null`, not a valid type, or if the
  /// first element of a list is not a string URI (VC-compliant).
  factory JsonLdContext.fromJson(Object? json) {
    if (json == null) {
      throw SsiException(
        message: '"@context" cannot be null',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (json is! String && json is! List) {
      throw SsiException(
        message:
            'Top-level @context must be a string URI or a list of URIs/maps',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    final normalized = json is List ? List<Object>.from(json) : json;

    // VC-compliant check: first element must be string if it's a list
    if (normalized is List && normalized.isNotEmpty) {
      final first = normalized.first;
      if (first is! String) {
        throw SsiException(
          message:
              'The first element of @context must be a string URI, but found ${first.runtimeType}',
          code: SsiExceptionType.invalidJson.code,
        );
      }
    }

    return JsonLdContext._(normalized);
  }

  /// Checks whether the context contains the given [url].
  ///
  /// Returns `true` if [context] matches [url] directly (when string), or
  /// if [url] is found as a string in a list of context elements.
  bool hasUrlContext(Uri url) {
    final urlStr = url.toString();
    if (context is String) return context == urlStr;
    if (context is List) {
      for (final element in context as List<dynamic>) {
        if (element is String && element == urlStr) return true;
      }
    }
    return false;
  }
}

/// Represents a mutable JSON-LD `@context`.
///
/// Unlike [JsonLdContext], this class allows modification of the stored context,
/// which can be a [Map], [List], or [String]. Mutations are performed by
/// directly updating the [context] property.
///
/// Example:
/// ```dart
/// final context = MutableJsonLdContext.fromJson(
///   {"@vocab": "https://schema.org/", "name": "schema:name"},
/// );
/// (context.context as Map)['age'] = 'schema:age';
/// print(context.toJson()); // {"@vocab": "https://schema.org/", "name":"schema:name", "age":"schema:age"}
/// ```
class MutableJsonLdContext extends _JsonLdContextInterface {
  /// The mutable stored JSON-LD context.
  @override
  Object context;

  /// Private constructor to enforce creation via `fromJson`.
  MutableJsonLdContext._(this.context);

  /// Returns the first string URI in the context.
  ///
  /// Works the same as [JsonLdContext.firstUri].
  @override
  Uri? get firstUri {
    if (context is String) return Uri.tryParse(context as String);

    if (context is List) {
      final list = context as List<dynamic>;
      if (list.isNotEmpty && list.first is String) {
        return Uri.tryParse(list.first as String);
      }
    }

    return null;
  }

  /// Creates a mutable JSON-LD context from a JSON object.
  ///
  /// Accepts a [String] URI, a [Map] of term definitions, or a [List] of URIs
  /// and/or term maps.
  ///
  /// Throws [SsiException] if [json] is `null`, not a valid type, or if the
  /// first element of a list is not a string URI (VC-compliant).
  factory MutableJsonLdContext.fromJson(Object? json) {
    if (json == null) {
      throw SsiException(
        message: '"@context" cannot be null',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (json is! String && json is! List) {
      throw SsiException(
        message:
            'Top-level @context must be a string URI or a list of URIs/maps',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    final normalized = json is List ? List<Object>.from(json) : json;

    // VC-compliant check: first element must be string if it's a list
    if (normalized is List && normalized.isNotEmpty) {
      final first = normalized.first;
      if (first is! String) {
        throw SsiException(
          message:
              'The first element of @context must be a string URI, but found ${first.runtimeType}',
          code: SsiExceptionType.invalidJson.code,
        );
      }
    }

    return MutableJsonLdContext._(normalized);
  }

  /// Checks whether the context contains the given [url].
  ///
  /// Returns `true` if [context] matches [url] directly (when string), or
  /// if [url] is found as a string in a list of context elements.
  bool hasUrlContext(Uri url) {
    final urlStr = url.toString();
    if (context is String) return context == urlStr;
    if (context is List) {
      for (final element in context as List<dynamic>) {
        if (element is String && element == urlStr) return true;
      }
    }
    return false;
  }

  /// Returns the current JSON representation of the context.
  @override
  Object toJson() => context;
}
