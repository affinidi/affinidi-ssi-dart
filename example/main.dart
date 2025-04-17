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
  final data = Uint8List.fromList([1, 2, 3]);
  print('data to sign: ${hexEncode(data)}');
  final signature = await wallet.sign(data, keyId: Bip32Wallet.rootKeyId);
  print('signature: ${hexEncode(signature)}');
  final isRootSignatureValid = await wallet.verify(data,
      signature: signature, keyId: Bip32Wallet.rootKeyId);
  print('check if root signature is valid: $isRootSignatureValid');

  // did
  final rootKey = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
  final rootDidKey = DidKey.generateDocument(rootKey);
  print('root did: ${rootDidKey.id}');

  // from derived key pair
  print("Signing and verifying from profile key");
  final profileKeyId = "1234-0";
  final profileKey = await wallet.generateKey(keyId: profileKeyId);
  final profileSignature = await wallet.sign(data, keyId: profileKeyId);
  print('profile signature: ${hexEncode(profileSignature)}');
  final isProfileSignatureValid = await wallet.verify(data,
      signature: profileSignature, keyId: profileKeyId);
  print(
      'check if profile signature is valid by public key: $isProfileSignatureValid');

  // did
  final profileDidKey = DidKey.generateDocument(profileKey);
  print('profile did: ${profileDidKey.id}');

  // second profile key
  print("Signing and verifying from second profile key");
  final profileKeyId2 = "1234-1";
  await wallet.generateKey(keyId: profileKeyId2);
  final profileSignature2 = await wallet.sign(data, keyId: profileKeyId2);
  print('profile signature 2: ${hexEncode(profileSignature2)}');
  final isProfileSignature2Valid = await wallet.verify(data,
      signature: profileSignature2, keyId: profileKeyId2);
  print(
      'check if profile signature 2 is valid by public key: $isProfileSignature2Valid');
}
