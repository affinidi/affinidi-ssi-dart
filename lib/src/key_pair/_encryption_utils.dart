import 'dart:typed_data';
import 'dart:math';

import 'package:pointycastle/export.dart' as pce;
import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:pointycastle/src/utils.dart' as p_utils;

class EncryptionUtils {
  final _ivLength = 16;
  final _blockSizeBytes = 16;
  final _secureRandom = pce.FortunaRandom();

  void _initializeSecureRandomSeed() {
    final seed = Uint8List.fromList(
      List.generate(32, (n) => Random.secure().nextInt(255)),
    );

    _secureRandom.seed(pc.KeyParameter(seed));
  }

  /// Constructor to initialize cryptography service with a secure random seed.
  EncryptionUtils() {
    _initializeSecureRandomSeed();
  }

  Uint8List aesCbcDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List cipherText,
    bool enforceAssertions = false,
  }) {
    // Started decrypting with AES CBC
    if (enforceAssertions) {
      assert(256 == key.length * 8);
      assert(128 == iv.length * 8);
      assert(cipherText.length * 8 % 128 == 0);
    }

    // Create a CBC block cipher with AES, and initialize with key and IV
    final cbc = pce.CBCBlockCipher(pce.AESEngine())
      ..init(
        false,
        pc.ParametersWithIV(pc.KeyParameter(key), iv),
      ); // false=decrypt

    final paddedPlainText = Uint8List(cipherText.length); // allocate space

    var offset = 0;

    while (offset < cipherText.length) {
      offset += cbc.processBlock(cipherText, offset, paddedPlainText, offset);
    }

    assert(offset == cipherText.length);

    // Completed decrypting with AES CBC
    return paddedPlainText;
  }

  Uint8List _aesCbcEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List paddedPlaintext,
    bool enforce256KeyLength = false,
    bool enforce128BitAlignment = false,
  }) {
    if (enforce256KeyLength) {
      // enforce 256-bit key length
      assert(256 == key.length * 8);
    } else {
      // allow 128, 192, or 256-bit key lengths
      assert([128, 192, 256].contains(key.length * 8));
    }

    assert(128 == iv.length * 8); // IV must be 128 bits

    if (enforce128BitAlignment) {
      // padded plaintext is a multiple of 128 bits
      assert(paddedPlaintext.length * 8 % 128 == 0);
    } else {
      // padded plaintext is exactly 128 bits
      assert(128 == paddedPlaintext.length * 8);
    }

    // Create a CBC block cipher with AES, and initialize with key and IV
    final cbc = pce.CBCBlockCipher(pce.AESEngine())
      ..init(
        true,
        pc.ParametersWithIV(pc.KeyParameter(key), iv),
      ); // true=encrypt

    final cipherText = Uint8List(paddedPlaintext.length); // allocate space

    var offset = 0;

    while (offset < paddedPlaintext.length) {
      offset += cbc.processBlock(paddedPlaintext, offset, cipherText, offset);
    }

    assert(offset == paddedPlaintext.length);

    return cipherText;
  }

  Uint8List encryptToBytes(Uint8List key, Uint8List data) {
    // Started encrypting to bytes
    final iv = _secureRandom.nextBytes(_ivLength);
    final bytes = _aesCbcEncrypt(
      key: key,
      iv: iv,
      paddedPlaintext: _pad(data, _blockSizeBytes),
      enforce256KeyLength: true,
      enforce128BitAlignment: true,
    );

    // Completed encrypting to bytes
    return Uint8List.fromList([...iv, ...bytes]);
  }

  Uint8List? decryptFromBytes(Uint8List key, Uint8List ivAndBytes) {
    // Started decrypting from bytes
    try {
      final iv = Uint8List.fromList(ivAndBytes.take(_ivLength).toList());
      final bytes = Uint8List.fromList(ivAndBytes.skip(_ivLength).toList());

      final decryptedAndPadding = aesCbcDecrypt(
        key: key,
        iv: iv,
        cipherText: bytes,
        enforceAssertions: true,
      );

      // Completed decrypting from bytes
      return _unpad(decryptedAndPadding);
    } catch (error) {
      return null;
    }
  }

  Uint8List _pad(List<int> bytes, int blockSizeBytes) {
    // The PKCS #7 padding just fills the extra bytes with the same value.
    // That value is the number of bytes of padding there is.
    //
    // For example, something that requires 3 bytes of padding with append
    // [0x03, 0x03, 0x03] to the bytes. If the bytes is already a multiple of the
    // block size, a full block of padding is added.

    final padLength = blockSizeBytes - (bytes.length % blockSizeBytes);
    final padded = Uint8List(bytes.length + padLength)..setAll(0, bytes);

    pce.PKCS7Padding().addPadding(padded, bytes.length);
    return padded;
  }

  Uint8List _unpad(Uint8List padded) {
    final unpadded =
        padded.sublist(0, padded.length - pce.PKCS7Padding().padCount(padded));
    return unpadded;
  }

  Uint8List unsignedIntToBytes(BigInt number) {
    assert(!number.isNegative);
    return p_utils.encodeBigIntAsUnsigned(number);
  }

  Uint8List intToBytes(BigInt number) => p_utils.encodeBigInt(number);
}
