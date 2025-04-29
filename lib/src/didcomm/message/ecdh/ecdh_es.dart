import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:elliptic/elliptic.dart' as ec;
import 'package:elliptic/ecdh.dart' as ecdh;
import 'package:crypto_keys/crypto_keys.dart' as ck;
import 'package:x25519/x25519.dart' as x25519;

import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/key_pair/_ecdh_profile.dart';

abstract class ECDHES implements ECDHProfile {
  final String? apu;
  final String? apv;
  final String enc;

  ECDHES({this.apu, this.apv, required this.enc});

  List<int> getEncryptionSecret(Uint8List privateKey);
  List<int> getDecryptionSecret(Uint8List privateKey);

  @override
  encryptData({
    required Uint8List privateKey,
    required Uint8List data,
  }) {
    final secret = getEncryptionSecret(privateKey);
    final sharedSecret = _generateSharedSecret(secret);

    final kw = _getKeyWrapEncrypter(sharedSecret);
    return kw.encrypt(data).data;
  }

  @override
  Uint8List decryptData({
    required Uint8List privateKey,
    required Uint8List data,
  }) {
    final secret = getDecryptionSecret(privateKey);
    final sharedSecret = _generateSharedSecret(secret);

    final kw = _getKeyWrapEncrypter(sharedSecret);
    return kw.decrypt(ck.EncryptionResult(data));
  }

  _generateSharedSecret(List<int> z) {
    //Didcomm only uses A256KW
    final keyDataLen = 256;
    final suppPubInfo = _int32BigEndianBytes(keyDataLen);

    final encAscii = ascii.encode('ECDH-ES+A256KW');
    final encLength = _int32BigEndianBytes(encAscii.length);

    List<int> partyU, partyULength;
    if (apu != null) {
      partyU = base64Decode(addPaddingToBase64(apu!));
      partyULength = _int32BigEndianBytes(partyU.length);
    } else {
      partyU = [];
      partyULength = _int32BigEndianBytes(0);
    }

    List<int> partyV, partyVLength;
    if (apv != null) {
      partyV = base64Decode(addPaddingToBase64(apv!));
      partyVLength = _int32BigEndianBytes(partyV.length);
    } else {
      partyV = [];
      partyVLength = _int32BigEndianBytes(0);
    }

    var otherInfo = encLength +
        encAscii +
        partyULength +
        partyU +
        partyVLength +
        partyV +
        suppPubInfo;

    var kdfIn = [0, 0, 0, 1] + z + otherInfo;
    var digest = sha256.convert(kdfIn);
    return digest.bytes;
  }

  ck.Encrypter _getKeyWrapEncrypter(List<int> sharedSecret) {
    Map<String, dynamic> sharedSecretJwk = {
      'kty': 'oct',
      'k': base64UrlEncode(sharedSecret)
    };

    final keyWrapKey = ck.KeyPair.fromJwk(sharedSecretJwk);
    return keyWrapKey.publicKey!
        .createEncrypter(ck.algorithms.encryption.aes.keyWrap);
  }

  Uint8List _int32BigEndianBytes(int value) =>
      Uint8List(4)..buffer.asByteData().setInt32(0, value, Endian.big);
}

class ECDHES_Elliptic extends ECDHES implements ECDHProfile {
  final ec.PublicKey publicKey;
  final Uint8List? privateKeyBytes;

  ECDHES_Elliptic({
    required this.publicKey,
    this.privateKeyBytes,
    super.apu,
    super.apv,
    required super.enc,
  });

  List<int> getEncryptionSecret(Uint8List _) {
    if (privateKeyBytes == null) {
      throw Exception('Private key needed for encryption data.');
    }

    final privateKey =
        ec.PrivateKey.fromBytes(publicKey.curve, privateKeyBytes!);
    return ecdh.computeSecret(privateKey, publicKey);
  }

  List<int> getDecryptionSecret(Uint8List privateKeyBytes) {
    final privateKey =
        ec.PrivateKey.fromBytes(publicKey.curve, privateKeyBytes);
    return ecdh.computeSecret(privateKey, publicKey);
  }
}

class ECDHES_X25519 extends ECDHES implements ECDHProfile {
  final List<int> publicKey;
  final Uint8List? privateKey;

  ECDHES_X25519({
    required this.publicKey,
    this.privateKey,
    super.apu,
    super.apv,
    required super.enc,
  });

  List<int> getEncryptionSecret(Uint8List _) {
    if (privateKey == null) {
      throw Exception('Private key needed for encryption data.');
    }

    return x25519.X25519(privateKey!, publicKey);
  }

  List<int> getDecryptionSecret(Uint8List privateKeyBytes) {
    return x25519.X25519(privateKeyBytes.sublist(0, 32), publicKey);
  }
}
