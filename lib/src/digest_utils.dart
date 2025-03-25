import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'types.dart';

class DigestUtils {
  static final Map<HashingAlgorithm, Digest> _digests = {
    HashingAlgorithm.sha256: Digest('SHA-256'),
    HashingAlgorithm.sha512: Digest('SHA-512'),
  };

  static Uint8List getDigest(
    Uint8List data, {
    HashingAlgorithm hashingAlgorithm = HashingAlgorithm.sha256,
  }) {
    return _digests[hashingAlgorithm]!.process(data);
  }
}
