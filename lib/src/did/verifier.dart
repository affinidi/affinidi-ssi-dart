import 'dart:typed_data';

abstract interface class Verifier {
  bool isAllowedAlgorithm(String algorithm);
  bool verify(Uint8List data, Uint8List signature);
}
