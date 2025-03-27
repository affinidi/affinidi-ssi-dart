import 'dart:convert';
import 'dart:math';

import 'package:sdjwt_sdk/src/base/generator.dart';

/// A generator that produces secure random Base64Url-encoded nonce strings.
///
/// This generator is useful for creating cryptographically secure random values
/// for use in authentication and security contexts.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
final class Base64NonceGenerator extends Generator<String> {
  /// The secure random number generator used to create nonce values.
  final _random = Random.secure();

  /// The length of the generated nonce string.
  final int length;

  /// The maximum value for each random byte (exclusive).
  final int max;

  /// Creates a new Base64NonceGenerator with the specified parameters.
  ///
  /// Parameters:
  /// - **[length]**: The length of the generated nonce string. Defaults to 32.
  /// - **[max]**: The maximum value for each random byte (exclusive). Defaults to 256.
  Base64NonceGenerator({this.length = 32, this.max = 256});

  @override
  String generate() {
    final values = List<int>.generate(length, (i) => _random.nextInt(256));
    return base64Url.encode(values).substring(0, length);
  }
}
