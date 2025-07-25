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
    if (value == null) {
      return 'null';
    } else if (value is bool) {
      return value ? 'true' : 'false';
    } else if (value is num) {
      return _canonicalizeNumber(value);
    } else if (value is String) {
      return _canonicalizeString(value);
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

  /// Canonicalizes a number according to ECMAScript 6 number formatting rules.
  ///
  /// Per RFC 8785, numbers are formatted using ECMAScript 6 Number.prototype.toString()
  /// rules which ensure a deterministic and interoperable representation.
  static String _canonicalizeNumber(num value) {
    if (value.isNaN) {
      throw SsiException(
        message: 'NaN is not allowed in JSON',
        code: SsiExceptionType.invalidJson.code,
      );
    }
    if (value.isInfinite) {
      throw SsiException(
        message: 'Infinity is not allowed in JSON',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    // Handle integers - simple decimal representation
    if (value is int) {
      return value.toString();
    }

    // Handle doubles
    if (value is double && value.isFinite) {
      // Check if the double represents an integer value
      if (value == value.truncateToDouble()) {
        // For very large numbers that exceed integer limits, keep as double
        if (value.abs() > 9007199254740991) {
          // JavaScript MAX_SAFE_INTEGER
          return value.toString().replaceAll('.0', '');
        }
        // Remove decimal point for integer values (e.g., 1.0 -> "1")
        return value.truncate().toString();
      }

      // For fractional values, use ECMAScript 6 compliant formatting
      // Dart's toString() generally produces ECMAScript-compatible output,
      // but we need to ensure no unnecessary trailing zeros
      String str = value.toString();

      // Handle scientific notation - convert to decimal if reasonable
      if (str.contains('e') || str.contains('E')) {
        // For very small or very large numbers, keep scientific notation
        // as per ECMAScript 6 rules
        return str;
      }

      // Remove trailing zeros after decimal point
      if (str.contains('.')) {
        str = str.replaceAll(RegExp(r'0+$'), '');
        // Remove decimal point if no fractional part remains
        str = str.replaceAll(RegExp(r'\.$'), '');
      }

      return str;
    }

    // Fallback (should not reach here for valid JSON numbers)
    return value.toString();
  }

  /// Canonicalizes a string by properly escaping characters.
  static String _canonicalizeString(String value) {
    final buffer = StringBuffer('"');

    for (int i = 0; i < value.length; i++) {
      final char = value[i];
      final codeUnit = value.codeUnitAt(i);

      switch (char) {
        case '"':
          buffer.write('\\"');
          break;
        case '\\':
          buffer.write('\\\\');
          break;
        case '\b':
          buffer.write('\\b');
          break;
        case '\f':
          buffer.write('\\f');
          break;
        case '\n':
          buffer.write('\\n');
          break;
        case '\r':
          buffer.write('\\r');
          break;
        case '\t':
          buffer.write('\\t');
          break;
        default:
          if (codeUnit < 0x20) {
            // Control characters must be escaped as \uXXXX
            buffer.write('\\u${codeUnit.toRadixString(16).padLeft(4, '0')}');
          } else {
            buffer.write(char);
          }
      }
    }

    buffer.write('"');
    return buffer.toString();
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

      buffer.write(_canonicalizeString(key));
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
