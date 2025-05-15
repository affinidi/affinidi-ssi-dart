import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );
  final dataToSign = Uint8List.fromList(utf8.encode('Hello, SSI!'));

  print('--- Bip32 Wallet with Mapping Transformer ---');

  // 1. Mapping Transformer
  Future<String> mappingTransformer(String id) async {
    final Map<String, String> keyIdToPathMap = {
      'userProfile': "m/44'/60'/0'/0'/0'",
      'deviceAuth': "m/44'/60'/0'/0'/1'",
    };
    if (keyIdToPathMap.containsKey(id)) {
      print('MappingTransformer: Mapping "$id" to "${keyIdToPathMap[id]}"');
      return keyIdToPathMap[id]!;
    }
    throw Exception('MappingTransformer: Unknown keyId: $id');
  }

  final walletWithMappingTransformer = Bip32Wallet.fromSeed(
    seed,
    keyIdToDerivationPathTransformer: mappingTransformer,
  );

  const userProfileKeyId = 'userProfile';
  print(
      'Generating key for ID: "$userProfileKeyId" using mapping transformer...');
  final userProfileKey =
      await walletWithMappingTransformer.generateKey(keyId: userProfileKeyId);
  print(
      'Generated key for "$userProfileKeyId". Public Key (hex): ${hexEncode(userProfileKey.publicKey.bytes.sublist(0, 5))}...');

  print('Signing data with key ID: "$userProfileKeyId"...');
  final signatureFromMapping = await walletWithMappingTransformer.sign(
    dataToSign,
    keyId: userProfileKeyId,
  );
  print('Signature (hex): ${hexEncode(signatureFromMapping.sublist(0, 8))}...');
  final isValidMapping = await walletWithMappingTransformer.verify(
    dataToSign,
    signature: signatureFromMapping,
    keyId: userProfileKeyId,
  );
  print('Signature verification result: $isValidMapping');
  assert(
      isValidMapping, 'Signature verification failed for mapping transformer');

  print('\n--- Bip32 Wallet with Hashing Transformer ---');

  // 2. Hashing Transformer
  Future<String> hashingTransformer(String id) async {
    // Use a cryptographic hash (e.g., SHA256) of the ID
    final idBytes = utf8.encode(id);
    final digest = sha256.convert(idBytes);
    final hashBytes = Uint8List.fromList(digest.bytes);

    // Take the first 4 bytes of the hash and interpret them as an unsigned 32-bit integer.
    // BIP32 path components should be < 2^31. We'll use a smaller part for simplicity.
    // Ensure the derived number is non-hardened (less than 0x80000000).
    final derivedIndex =
        ByteData.view(hashBytes.buffer).getUint32(0, Endian.big) & 0x7FFFFFFF;

    // Construct a derivation path. For example, using a fixed prefix.
    // m/purpose'/coin_type'/account'/change/address_index
    // We'll use a simple path like m/44'/0'/0'/0/<derived_index_from_hash>
    final path = "m/44'/0'/0'/0/$derivedIndex";
    print(
        'HashingTransformer: Transformed "$id" (hash index $derivedIndex) to path "$path"');
    return path;
  }

  final walletWithHashingTransformer = Bip32Wallet.fromSeed(
    seed,
    keyIdToDerivationPathTransformer: hashingTransformer,
  );

  const dynamicKeyId = 'myInvoice#12345';
  print('Generating key for ID: "$dynamicKeyId" using hashing transformer...');
  final dynamicKey =
      await walletWithHashingTransformer.generateKey(keyId: dynamicKeyId);
  print(
      'Generated key for "$dynamicKeyId". Public Key (hex): ${hexEncode(dynamicKey.publicKey.bytes.sublist(0, 5))}...');

  print('Signing data with key ID: "$dynamicKeyId"...');
  final signatureFromHashing = await walletWithHashingTransformer.sign(
    dataToSign,
    keyId: dynamicKeyId,
  );
  print('Signature (hex): ${hexEncode(signatureFromHashing.sublist(0, 8))}...');
  final isValidHashing = await walletWithHashingTransformer.verify(
    dataToSign,
    signature: signatureFromHashing,
    keyId: dynamicKeyId,
  );
  print('Signature verification result: $isValidHashing');
  assert(
      isValidHashing, 'Signature verification failed for hashing transformer');

  // Example of a different ID producing a different key
  const anotherDynamicKeyId = 'myInvoice#67890';
  print(
      '\nGenerating key for different ID: "$anotherDynamicKeyId" using hashing transformer...');
  final anotherDynamicKey = await walletWithHashingTransformer.generateKey(
      keyId: anotherDynamicKeyId);
  print(
      'Generated key for "$anotherDynamicKeyId". Public Key (hex): ${hexEncode(anotherDynamicKey.publicKey.bytes.sublist(0, 5))}...');
  assert(
      hexEncode(dynamicKey.publicKey.bytes) !=
          hexEncode(anotherDynamicKey.publicKey.bytes),
      'Keys for different IDs should be different with hashing transformer');
  print('Keys for different IDs are indeed different.');
}
