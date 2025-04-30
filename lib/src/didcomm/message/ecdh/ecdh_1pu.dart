import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:elliptic/elliptic.dart' as ec;
import 'package:elliptic/ecdh.dart' as ecdh;
import 'package:crypto_keys/crypto_keys.dart' as ck;
import 'package:x25519/x25519.dart' as x25519;

import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/key_pair/_ecdh_profile.dart';

abstract class ECDH1PU implements ECDHProfile {
  final List<int> authenticationTag;
  final KeyWrapAlgorithm keyWrapAlgorithm;
  final String apu;
  final String apv;

  ECDH1PU(
      {required this.authenticationTag,
      required this.keyWrapAlgorithm,
      required this.apu,
      required this.apv});

  ({Uint8List ze, Uint8List zs}) getEncryptionSecrets(Uint8List privateKey);
  ({Uint8List ze, Uint8List zs}) getDecryptionSecrets(Uint8List privateKey);

  @override
  encryptData({
    required Uint8List privateKey,
    required Uint8List data,
  }) {
    final secrets = getEncryptionSecrets(privateKey);
    final sharedSecret = _generateSharedSecret(secrets.ze, secrets.zs);

    final kw = _getKeyWrapEncrypter(sharedSecret);
    return kw.encrypt(data).data;
  }

  @override
  Uint8List decryptData({
    required Uint8List privateKey,
    required Uint8List data,
  }) {
    final secrets = getDecryptionSecrets(privateKey);
    final sharedSecret = _generateSharedSecret(secrets.ze, secrets.zs);

    final kw = _getKeyWrapEncrypter(sharedSecret);
    return kw.decrypt(ck.EncryptionResult(data));
  }

  List<int> _generateSharedSecret(List<int> ze, List<int> zs) {
    var z = ze + zs;

    //Didcomm only uses A256KW
    final keyDataLen = 256;
    final cctagLen = _int32BigEndianBytes(authenticationTag.length);
    final suppPubInfo =
        _int32BigEndianBytes(keyDataLen) + cctagLen + authenticationTag;

    final encAscii = ascii.encode(keyWrapAlgorithm.value);
    final encLength = _int32BigEndianBytes(encAscii.length);

    final partyU = base64Decode(addPaddingToBase64(apu));
    final partyULength = _int32BigEndianBytes(partyU.length);

    final partyV = base64Decode(addPaddingToBase64(apv));
    final partyVLength = _int32BigEndianBytes(partyV.length);

    final otherInfo = encLength +
        encAscii +
        partyULength +
        partyU +
        partyVLength +
        partyV +
        suppPubInfo;

    final kdfIn = [0, 0, 0, 1] + z + otherInfo;
    return sha256.convert(kdfIn).bytes;
  }

  ck.Encrypter _getKeyWrapEncrypter(List<int> sharedSecret) {
    final sharedSecretJwk = {'kty': 'oct', 'k': base64UrlEncode(sharedSecret)};
    final keyWrapKey = ck.KeyPair.fromJwk(sharedSecretJwk);

    return keyWrapKey.publicKey!
        .createEncrypter(ck.algorithms.encryption.aes.keyWrap);
  }

  Uint8List _int32BigEndianBytes(int value) =>
      Uint8List(4)..buffer.asByteData().setInt32(0, value, Endian.big);
}

class ECDH1PU_Elliptic extends ECDH1PU implements ECDHProfile {
  final ec.PublicKey public1;
  final ec.PublicKey public2;
  final ec.PrivateKey? private1;

  ECDH1PU_Elliptic(
      {required super.authenticationTag,
      required super.keyWrapAlgorithm,
      required super.apu,
      required super.apv,
      required this.public1,
      required this.public2,
      this.private1});

  ({Uint8List ze, Uint8List zs}) getEncryptionSecrets(
      Uint8List privateKeyBytes) {
    if (private1 == null) {
      throw Exception('Private key needed for encryption data.');
    }

    final privateKey = ec.PrivateKey.fromBytes(public1.curve, privateKeyBytes);

    final ze = ecdh.computeSecret(private1!, public1);
    final zs = ecdh.computeSecret(privateKey, public2);
    return (ze: Uint8List.fromList(ze), zs: Uint8List.fromList(zs));
  }

  ({Uint8List ze, Uint8List zs}) getDecryptionSecrets(
      Uint8List privateKeyBytes) {
    final privateKey = ec.PrivateKey.fromBytes(public1.curve, privateKeyBytes);

    final ze = ecdh.computeSecret(privateKey, public1);
    final zs = ecdh.computeSecret(privateKey, public2);

    return (ze: Uint8List.fromList(ze), zs: Uint8List.fromList(zs));
  }
}

class ECDH1PU_X25519 extends ECDH1PU {
  final List<int> public1;
  final List<int> public2;
  final List<int>? private1;

  ECDH1PU_X25519(
      {required super.authenticationTag,
      required super.keyWrapAlgorithm,
      required super.apu,
      required super.apv,
      required this.public1,
      required this.public2,
      this.private1});

  ({Uint8List ze, Uint8List zs}) getEncryptionSecrets(Uint8List private2) {
    if (private1 == null) {
      throw Exception('Private key needed for encryption data.');
    }

    final ze = x25519.X25519(private1!.sublist(0, 32), public1);
    final zs = x25519.X25519(private2.sublist(0, 32), public2);
    return (ze: ze, zs: zs);
  }

  ({Uint8List ze, Uint8List zs}) getDecryptionSecrets(Uint8List private2) {
    final ze = x25519.X25519(private2.sublist(0, 32), public1);
    final zs = x25519.X25519(private2.sublist(0, 32), public2);
    return (ze: ze, zs: zs);
  }
}
