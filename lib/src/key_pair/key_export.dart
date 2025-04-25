import 'dart:typed_data';

/// Internal use only
abstract class KeyExport {
  /// Returns the private key as [Uint8List].
  Future<Uint8List> get privateKey;
}
