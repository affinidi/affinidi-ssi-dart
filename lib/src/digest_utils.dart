import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'types.dart';

/// Utility class for digest operations.
class DigestUtils {
  /// The map of hashing algorithms to digest instances.
  static final Map<HashingAlgorithm, Digest> _digests = {
    HashingAlgorithm.sha256: Digest('SHA-256'),
    HashingAlgorithm.sha384: Digest('SHA-384'),
    HashingAlgorithm.sha512: Digest('SHA-512'),
  };

  /// Returns the digest of the given data using the specified hashing algorithm.
  static Uint8List getDigest(
    Uint8List data, {
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  }) {
    return _digests[hashingAlgorithm]!.process(data);
  }
}
