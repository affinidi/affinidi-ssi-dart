import 'dart:collection';

import 'package:meta/meta.dart';
import 'package:sdjwt_sdk/src/models/disclosure.dart';

import '../base/hasher.dart';

/// A specialized map implementation for managing disclosures, indexed by their digest values.
/// Extends [MapBase] to provide standard map functionality while adding specific
/// handling for disclosure objects.
@immutable
class DisclosureMap extends MapBase<String, Disclosure> {
  /// The internal map storing disclosures with their digest as keys.
  final Map<String, Disclosure> disclosureMap;

  /// Creates a mutable DisclosureMap so that disclosures can be added to this with normalized digests
  /// This helps us support both padded / non padded digests transparently.
  DisclosureMap._mutable() : disclosureMap = {};

  /// Converts a mutable DisclosureMap to an unmodifiable one after the SdJwt is constructed.
  /// This helps us make the SdJwt as well as all it's fields unmodifiable. Any public
  /// DisclosureMap factory should always return an unmodifiable map.
  ///
  /// Parameters:
  /// - **[disclosures]**: A mutable DisclosureMap to be made unmodifiable.
  ///
  /// Returns unmodifiable DisclosureMap
  DisclosureMap._unmodifiable({required DisclosureMap disclosures})
      : disclosureMap =
            Map<String, Disclosure>.unmodifiable(disclosures.disclosureMap);

  /// Normalizes a key to ensure consistent lookup in the map.
  ///
  /// Parameters:
  /// - **[key]**: The key to normalize.
  ///
  /// Returns the normalized key as a string, or null if the key is null.
  String? normalizeKey(Object? key) {
    if (key == null) return null;

    return key.toString().replaceAll('=', '');
  }

  @override
  Disclosure? operator [](Object? key) => disclosureMap[normalizeKey(key)];

  @override
  void operator []=(String key, Disclosure value) =>
      disclosureMap[normalizeKey(key)!] = value;

  @override
  void clear() => disclosureMap.clear();

  @override
  Iterable<String> get keys => disclosureMap.keys;

  @override
  Iterable<Disclosure> get values => disclosureMap.values;

  @override
  Iterable<MapEntry<String, Disclosure>> get entries => disclosureMap.entries;

  @override
  bool containsKey(Object? key) => disclosureMap.containsKey(normalizeKey(key));

  @override
  Disclosure? remove(Object? key) => disclosureMap.remove(normalizeKey(key));

  /// Creates a [DisclosureMap] by parsing a set of disclosure strings.
  ///
  /// Parameters:
  /// - **[disclosureStrings]**: A set of serialized disclosure strings to parse.
  /// - **[hasher]**: The [Hasher] used for the disclosures.
  factory DisclosureMap.parse(
      Set<String> disclosureStrings, Hasher<String, String> hasher) {
    final disclosureMap = DisclosureMap._mutable();

    for (final disclosure in disclosureStrings) {
      final d = Disclosure.parse(disclosure, hasher);
      disclosureMap[d.digest] = d;
    }

    return DisclosureMap._unmodifiable(disclosures: disclosureMap);
  }

  /// Creates a [DisclosureMap] from an existing set of [Disclosure] objects.
  ///
  /// Parameters:
  /// - **[disclosures]**: A set of disclosure objects to include in the map.
  factory DisclosureMap.from(Set<Disclosure> disclosures) {
    final disclosureMap = DisclosureMap._mutable();

    for (final d in disclosures) {
      disclosureMap[d.digest] = d;
    }

    return DisclosureMap._unmodifiable(disclosures: disclosureMap);
  }
}
