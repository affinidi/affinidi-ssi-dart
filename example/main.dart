import 'dart:typed_data';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final wallet = Bip32Wallet.fromSeed(seed);

  // from wallet with root key
  print("Signing and verifying from root key");
  final rootKeyId = "0-0";
  final data = Uint8List.fromList([1, 2, 3]);
  print('data to sign: ${hexEncode(data)}');
  final signature = await wallet.sign(data, keyId: rootKeyId);
  print('signature: ${hexEncode(signature)}');
  final isRootSignatureValid =
      await wallet.verify(data, signature: signature, keyId: rootKeyId);
  print('check if root signature is valid: $isRootSignatureValid');

  // did
  final rootKeyPair = await wallet.getKeyPair(rootKeyId);
  final rootDidKey = await DidKey.create([rootKeyPair]);
  print('root did: $rootDidKey');
  final rootPublicKeyFromDid = await rootDidKey.publicKey;
  print('public key from root did: ${hexEncode(rootPublicKeyFromDid)}');

  // from derived key pair
  print("Signing and verifying from profile key");
  // NOTE: how to know what is the next available account index?
  final profileKeyId = "1234-0";
  final profileKeyPair = await wallet.createKeyPair(profileKeyId);
  final profileSignature = await profileKeyPair.sign(data);
  print('profile signature: ${hexEncode(profileSignature)}');
  final isProfileSignatureValid =
      await profileKeyPair.verify(data, signature: profileSignature);
  print(
      'check if profile signature is valid by public key: $isProfileSignatureValid');

  // did
  final profileDidKey = await DidKey.create([profileKeyPair]);
  print('profile did: $profileDidKey');
  final profilePublicKeyFromDid = await profileDidKey.publicKey;
  print('public key from profile did: ${hexEncode(profilePublicKeyFromDid)}');

  // second profile key
  print("Signing and verifying from second profile key");
  final profileKeyId2 = "1234-1";
  final profileKeyPair2 = await wallet.createKeyPair(profileKeyId2);
  final profileSignature2 = await profileKeyPair2.sign(data);
  print('profile signature 2: ${hexEncode(profileSignature2)}');
  final isProfileSignature2Valid =
      await profileKeyPair2.verify(data, signature: profileSignature2);
  print(
      'check if profile signature 2 is valid by public key: $isProfileSignature2Valid');
}
