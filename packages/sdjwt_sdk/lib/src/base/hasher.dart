import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'action.dart';

/// [CustomHasher] is a function pointer to a customized hasher.
typedef CustomHasher = Hasher<String, Uint8List>? Function(
    String algorithmName);

/// [Hasher] is an interface for hashing algorithms. It provides a way to
/// execute a specific algorithm on input data.
///
/// This class defines the contract for all hashers in the sdjwt_sdk library.
abstract interface class Hasher<T, V> extends Action<T, V> {
  /// Returns the name of the hasher as a string.
  String get name;

  /// [sha256] is an instance of the SHA-256 hashing algorithm.
  static const sha256 = _SHA256();

  /// [sha384] is an instance of the SHA-384 hashing algorithm.
  static const sha384 = _SHA384();

  /// [sha512] is an instance of the SHA-512 hashing algorithm.
  static const sha512 = _SHA512();

  /// [sha512_256] is an instance of the SHA-512-256 hashing algorithm.
  static const sha512_256 = _SHA512256();

  /// This map contains all bundled hashers, keyed by their name as a string.
  static final bundledHashersMap = {
    sha256.name: sha256,
    sha384.name: sha384,
    sha512.name: sha512,
    sha512_256.name: sha512_256,
  };

  /// Returns a list of all bundled hashers, which can be used to determine the
  /// available algorithms.
  static List<Hasher<String, Uint8List>> get bundledHashers =>
      List.unmodifiable(bundledHashersMap.values);

  /// Creates a new [Hasher] instance based on the provided name and optional custom
  /// hasher function. If overrideDefault is true, the custom hasher function takes
  /// precedence over the default hasher for this algorithm.
  static Hasher<String, Uint8List> fromString(String name,
      {CustomHasher? customHasher}) {
    if (customHasher != null) {
      return customHasher(name) ?? bundledHashersMap[name] ?? sha256;
    }
    return bundledHashersMap[name] ?? customHasher?.call(name) ?? sha256;
  }
}

/// A hasher implementation that wraps another hasher and encodes its output using a codec.
class Base64EncodedOutputHasher implements Hasher<String, String> {
  /// The underlying hasher instance.
  final Hasher<String, Uint8List> _underlyingHasher;

  /// The codec used to encode the output of this hasher.
  final Codec<List<int>, String> _encoder = Base64Codec.urlSafe();

  /// A base64 SHA-256 hasher instance.
  static final Base64EncodedOutputHasher base64Sha256 =
      Base64EncodedOutputHasher(Hasher.sha256);

  /// A base64 SHA-384 hasher instance.
  static final Base64EncodedOutputHasher base64Sha384 =
      Base64EncodedOutputHasher(Hasher.sha384);

  /// A base64 SHA-512 hasher instance.
  static final Base64EncodedOutputHasher base64Sha512 =
      Base64EncodedOutputHasher(Hasher.sha512);

  /// A base64 SHA-512-256 hasher instance.
  static final Base64EncodedOutputHasher base64Sha512_256 =
      Base64EncodedOutputHasher(Hasher.sha512_256);

  /// Creates a new instance of this hasher with the specified underlying hasher and codec.
  Base64EncodedOutputHasher(Hasher<String, Uint8List> hasher)
      : _underlyingHasher = hasher;

  /// Executes the wrapped hashing algorithm on the input data and returns its encoded
  /// output.
  @override
  String execute(String input) {
    final digest = _underlyingHasher.execute(input);
    return _encoder.encode(digest).replaceAll('=', '');
  }

  /// Returns the name of this hasher as a string, based on its underlying hasher.
  @override
  String get name => _underlyingHasher.name;
}

/// An implementation of the SHA-256 hashing algorithm.
class _SHA256 implements Hasher<String, Uint8List> {
  const _SHA256();

  /// Returns the name of this hasher as a string.
  @override
  String get name => 'sha-256';

  /// Executes the SHA-256 hashing algorithm on the input data and returns its
  /// digest.
  @override
  Uint8List execute(String input) {
    return Uint8List.fromList(sha256.convert(utf8.encode(input)).bytes);
  }
}

/// An implementation of the SHA-384 hashing algorithm.
class _SHA384 implements Hasher<String, Uint8List> {
  const _SHA384();

  /// Returns the name of this hasher as a string.
  @override
  String get name => 'sha-384';

  @override
  Uint8List execute(String input) {
    return Uint8List.fromList(sha384.convert(utf8.encode(input)).bytes);
  }
}

/// An implementation of the SHA-512 hashing algorithm.
class _SHA512 implements Hasher<String, Uint8List> {
  const _SHA512();

  /// Returns the name of this hasher as a string.
  @override
  String get name => 'sha-512';

  @override
  Uint8List execute(String input) {
    return Uint8List.fromList(sha512.convert(utf8.encode(input)).bytes);
  }
}

/// An implementation of the SHA-512-256 hashing algorithm.
class _SHA512256 implements Hasher<String, Uint8List> {
  const _SHA512256();

  /// Returns the name of this hasher as a string.
  @override
  String get name => 'sha-512-256';

  @override
  Uint8List execute(String input) {
    return Uint8List.fromList(sha512256.convert(utf8.encode(input)).bytes);
  }
}
