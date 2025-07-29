import 'dart:convert';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

/// JSON Canonicalization Scheme (JCS) implementation according to RFC 8785.
///
/// This utility provides canonicalization of JSON data structures according to
/// the JSON Canonicalization Scheme specification, which is used for creating
/// deterministic serializations for cryptographic operations.
class JcsUtil {
  /// Canonicalizes a JSON value according to RFC 8785 (JCS).
  ///
  /// [value] The JSON value to canonicalize (Map, List, String, num, bool, or null).
  ///
  /// Returns the canonicalized JSON string representation.
  ///
  /// Throws [SsiException] if the value contains unsupported types.
  static String canonicalize(dynamic value) {
    return _canonicalizeValue(value);
  }

  /// Internal method to canonicalize a value recursively.
  static String _canonicalizeValue(dynamic value) {
    if (value == null || value is bool || value is String) {
      return jsonEncode(value);
    } else if (value is num) {
      return _canonicalizeNumber(value);
    } else if (value is List) {
      return _canonicalizeArray(value);
    } else if (value is Map) {
      return _canonicalizeObject(value);
    } else {
      throw SsiException(
        message: 'Unsupported type: ${value.runtimeType}',
        code: SsiExceptionType.invalidJson.code,
      );
    }
  }

  /// Canonicalizes a number according to JCS rules.
  static String _canonicalizeNumber(num value) {
    // Handle special cases (NaN, Infinity)
    if (value.isNaN || value.isInfinite) {
      throw SsiException(
        message:
            'Invalid number: $value (NaN and Infinity are not allowed in JCS)',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    // Use jsonEncode but handle whole number doubles per JCS requirements
    final result = jsonEncode(value);

    // JCS requires whole numbers to be represented without .0 suffix
    if (result.endsWith('.0')) {
      return result.substring(0, result.length - 2);
    }

    return result;
  }

  /// Canonicalizes an array by recursively canonicalizing elements.
  static String _canonicalizeArray(List<dynamic> array) {
    final buffer = StringBuffer('[');

    for (int i = 0; i < array.length; i++) {
      if (i > 0) {
        buffer.write(',');
      }
      buffer.write(_canonicalizeValue(array[i]));
    }

    buffer.write(']');
    return buffer.toString();
  }

  /// Canonicalizes an object by sorting keys lexicographically and recursing.
  static String _canonicalizeObject(Map<dynamic, dynamic> object) {
    final buffer = StringBuffer('{');

    // Convert all keys to strings and sort them lexicographically
    final sortedKeys = object.keys.map((key) => key.toString()).toList()
      ..sort();

    for (int i = 0; i < sortedKeys.length; i++) {
      if (i > 0) {
        buffer.write(',');
      }

      final key = sortedKeys[i];
      final value = object[key] ?? object[_findOriginalKey(object, key)];

      buffer.write(jsonEncode(key));
      buffer.write(':');
      buffer.write(_canonicalizeValue(value));
    }

    buffer.write('}');
    return buffer.toString();
  }

  /// Finds the original key in the map that matches the string representation.
  static dynamic _findOriginalKey(
      Map<dynamic, dynamic> object, String keyString) {
    for (final key in object.keys) {
      if (key.toString() == keyString) {
        return key;
      }
    }
    return keyString;
  }
}
