import 'dart:collection';

import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';

/// Interface for JSON-LD `@context`.
///
/// Provides access to the list of context URIs and merged term definitions,
/// along with a method to serialize back to JSON.
abstract interface class _JsonLdContextInterface {
  /// Context URIs in encounter order.
  List<Uri> get uris;

  /// Merged term and reserved-key mappings (e.g., `"@vocab"`, `"@base"`, `"name"`).
  Map<String, Object?> get terms;

  /// Map-style access to [terms].
  Object? operator [](Object? key);

  /// Keys of [terms].
  Iterable<String> get keys;

  /// Converts this context back to a JSON-serializable `@context` object.
  ///
  /// Returns:
  /// - `[]` of URI strings when only URIs are present,
  /// - the terms object when only terms are present,
  /// - `[uris..., terms]` when both are present,
  /// - `{}` when empty.
  Object? toJson();
}

/// Represents an immutable JSON-LD `@context`.
///
/// A JSON-LD context defines mappings from terms to IRIs, along with reserved
/// keywords. This class parses and stores both context URIs and merged terms.
///
/// Example:
/// ```dart
/// final context = JsonLdContext.fromJson(
///   ["https://www.w3.org/ns/credentials/v2", {"@vocab":"https://schema.org/"}],
/// );
/// print(context.uris);   // [https://www.w3.org/ns/credentials/v2]
/// print(context.terms);  // {@vocab: https://schema.org/}
/// ```
class JsonLdContext extends _JsonLdContextInterface {
  @override
  final UnmodifiableListView<Uri> uris;

  @override
  final UnmodifiableMapView<String, Object?> terms;

  JsonLdContext._(this.uris, this.terms);

  /// Creates a [JsonLdContext] from JSON data.
  ///
  /// Accepts a JSON value representing a `@context`:
  /// - string  a single URI
  /// - object  term mappings
  /// - array   mix of URIs and objects
  ///
  /// Example:
  /// ```dart
  /// final context = JsonLdContext.fromJson("https://www.w3.org/2018/credentials/v1");
  /// ```
  factory JsonLdContext.fromJson(Object? json) {
    final uris = <Uri>[];
    final terms = <String, Object?>{};

    void process(Object? ctx) {
      if (ctx is String) {
        uris.add(Uri.parse(ctx));
      } else if (ctx is List) {
        for (final item in ctx) {
          process(item);
        }
      } else if (ctx is Map) {
        ctx.forEach((key, val) {
          terms[key as String] = val;
        });
      } else if (ctx == null) {
        // JSON-LD allows explicit context reset.
      } else {
        throw SsiException(
          message: 'Unsupported @context type: ${ctx.runtimeType}',
          code: SsiExceptionType.unsupportedContext.code,
        );
      }
    }

    process(json);

    return JsonLdContext._(
      UnmodifiableListView(uris),
      UnmodifiableMapView(terms),
    );
  }

  @override
  Object? operator [](Object? key) => terms[key];

  @override
  Iterable<String> get keys => terms.keys;

  @override
  Object? toJson() {
    final hasTerms = terms.isNotEmpty;

    if (!hasTerms) {
      if (uris.isEmpty) return {};
      return uris.map((u) => u.toString()).toList();
    }

    if (uris.isEmpty) return terms;

    final list = <Object>[];
    list.addAll(uris.map((u) => u.toString()));
    list.add(terms);
    return list.length == 1 ? list.first : list;
  }
}

/// Represents a mutable JSON-LD `@context`.
///
/// Unlike [JsonLdContext], this class allows modification of [uris] and [terms].
///
/// Example:
/// ```dart
/// final context = MutableJsonLdContext.fromJson(
///   {"@vocab": "https://schema.org/", "name": "schema:name"},
/// );
/// context.terms["age"] = "schema:age";
/// ```
class MutableJsonLdContext extends _JsonLdContextInterface {
  @override
  final List<Uri> uris;

  @override
  final Map<String, Object?> terms;

  MutableJsonLdContext._(this.uris, this.terms);

  /// Creates a [MutableJsonLdContext] from JSON data.
  ///
  /// Accepts a JSON value representing a `@context`:
  /// - string  a single URI
  /// - object  term mappings
  /// - array   mix of URIs and objects
  factory MutableJsonLdContext.fromJson(Object? json) {
    final uris = <Uri>[];
    final terms = <String, Object?>{};

    void process(Object? ctx) {
      if (ctx is String) {
        uris.add(Uri.parse(ctx));
      } else if (ctx is List) {
        for (final item in ctx) {
          process(item);
        }
      } else if (ctx is Map) {
        ctx.forEach((key, val) {
          terms[key as String] = val;
        });
      } else if (ctx == null) {
        // JSON-LD allows explicit context reset.
      } else {
        throw SsiException(
          message: 'Unsupported @context type: ${ctx.runtimeType}',
          code: SsiExceptionType.unsupportedContext.code,
        );
      }
    }

    process(json);

    return MutableJsonLdContext._(uris, terms);
  }

  @override
  Object? operator [](Object? key) => terms[key];

  @override
  Iterable<String> get keys => terms.keys;

  @override
  Object? toJson() {
    final hasTerms = terms.isNotEmpty;

    if (!hasTerms) {
      if (uris.isEmpty) return {};
      return uris.map((u) => u.toString()).toList();
    }

    if (uris.isEmpty) return terms;

    final list = <Object>[];
    list.addAll(uris.map((u) => u.toString()));
    list.add(terms);
    return list.length == 1 ? list.first : list;
  }
}
