import 'dart:typed_data';

abstract interface class ECDHProfile {
  Uint8List encryptData(
      {required Uint8List privateKey, required Uint8List data});

  Uint8List decryptData(
      {required Uint8List privateKey, required Uint8List data});
}
