import '../../ssi.dart';
import 'package:meta/meta.dart';

/// Represents a Decentralized Identifier (DID) URL.
///
/// A DID URL consists of a scheme, method, method-specific-id, and optional path, query, and fragment.
/// Provides parsing, stringification, and query parameter utilities for DID URLs.
abstract class DidUrl {
  /// The URI scheme, typically 'did'.
  String scheme;

  /// The DID method (e.g., 'web', 'key', etc.).
  String method;

  /// The method-specific identifier.
  String methodSpecificId;

  /// Optional path component.
  String? path;

  /// Optional query component (without '?').
  String? query;

  /// Optional fragment component (without '#').
  String? fragment;

  /// Constructs a [DidUrl] with the given components.
  @protected
  DidUrl.internal({
    required this.scheme,
    required this.method,
    required this.methodSpecificId,
    this.path,
    this.query,
    this.fragment,
  });

  /// Parses a DID URL string and returns its components as a record.
  ///
  /// Returns a record containing scheme, method, methodSpecificId, path, query, and fragment.
  /// Throws [FormatException] if the string is not a valid DID URL.
  static ({
    String scheme,
    String method,
    String methodSpecificId,
    String? path,
    String? query,
    String? fragment,
  }) fromUrlString(String urlString) {
    if (!urlString.startsWith('did:')) {
      throw FormatException(
          'Invalid DID URL: must start with "did:"', urlString);
    }

    // Extract fragment first
    String? fragment;
    String remaining = urlString;
    final fragmentIndex = remaining.indexOf('#');
    if (fragmentIndex != -1) {
      fragment = remaining.substring(fragmentIndex + 1);
      remaining = remaining.substring(0, fragmentIndex);
    }

    // Extract query
    String? query;
    final queryIndex = remaining.indexOf('?');
    if (queryIndex != -1) {
      query = remaining.substring(queryIndex + 1);
      remaining = remaining.substring(0, queryIndex);
    }

    // Extract path (after method-specific-id)
    String? path;
    final firstSlashIndex = remaining.indexOf('/', 4); // Start after "did:"
    if (firstSlashIndex != -1) {
      path = remaining.substring(firstSlashIndex);
      remaining = remaining.substring(0, firstSlashIndex);
    }

    // Parse DID: did:method:method-specific-id
    final withoutScheme = remaining.substring(4); // Remove "did:"
    final colonIndex = withoutScheme.indexOf(':');

    if (colonIndex == -1) {
      throw FormatException(
        'Invalid DID URL: must contain method and method-specific-id',
        urlString,
      );
    }

    final method = withoutScheme.substring(0, colonIndex);
    final methodSpecificId = withoutScheme.substring(colonIndex + 1);

    if (method.isEmpty) {
      throw FormatException(
          'Invalid DID URL: method cannot be empty', urlString);
    }
    if (methodSpecificId.isEmpty) {
      throw FormatException(
        'Invalid DID URL: method-specific-id cannot be empty',
        urlString,
      );
    }
    return (
      scheme: 'did',
      method: method,
      methodSpecificId: methodSpecificId,
      path: path,
      query: query,
      fragment: fragment,
    );
  }

  /// Returns the query parameters as a map.
  ///
  /// If [query] is null, returns an empty map.
  Map<String, String> get queryParameters =>
      query != null ? Uri.splitQueryString(query!) : {};

  /// Returns the base DID string (without path, query, or fragment).
  String toDidString() {
    return '$scheme:$method:$methodSpecificId';
  }

  /// Returns the full DID URL string, including optional path, query, and fragment.
  String toDidUrlString() {
    final buffer = StringBuffer();
    buffer.write('$scheme:$method:$methodSpecificId');
    if (path != null) {
      buffer.write(path);
    }
    if (query != null) {
      buffer.write('?$query');
    }
    if (fragment != null) {
      buffer.write('#$fragment');
    }
    return buffer.toString();
  }

  /// Resolves the DID document for this DID.
  ///
  /// Optionally accepts [DidResolutionOptions] to customize the resolution process.
  ///
  /// Returns a [Future] that completes with the resolved [DidDocument].
  ///
  /// Throws an exception if the DID cannot be resolved.
  Future<DidDocument> resolve([DidResolutionOptions? options]) async {
    throw UnimplementedError(
        'resolveDid() is not implemented in the base DidUrl class. '
        'DID resolution must be implemented by method-specific subclasses.');
  }
}
