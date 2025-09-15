import 'dart:convert';

import 'package:ssi/src/did/did_manager/did_web_manager.dart';
import 'package:ssi/src/did/stores/in_memory_did_store.dart';
import 'package:ssi/src/wallet/persistent_wallet.dart';
import 'package:ssi/src/wallet/stores/key_store_interface.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final wallet = PersistentWallet(InMemoryKeyStore());
  final didManager = DidWebManager(store: InMemoryDidStore(), wallet: wallet);

  final publicKey = await wallet.generateKey(
      keyId: 'did:web:localhost#1', keyType: KeyType.p256);
  await didManager.addVerificationMethod(publicKey.id);

  final publicKey2 = await wallet.generateKey(
      keyId: 'did:web:localhost#2', keyType: KeyType.secp256k1);
  await didManager.addVerificationMethod(publicKey2.id);

  await didManager.addServiceEndpoint(
    ServiceEndpoint(
      id: 'did:web:meetingplace.world#auth',
      type: 'Authentication',
      serviceEndpoint: const StringEndpoint(
          'https://ib8w1f44k7.execute-api.ap-southeast-1.amazonaws.com/dev/mpx/v1/authenticate'),
    ),
  );

  await didManager.addServiceEndpoint(
    ServiceEndpoint(
      id: 'did:web:meetingplace.world#api',
      type: 'RestAPI',
      serviceEndpoint: const StringEndpoint(
          'https://ib8w1f44k7.execute-api.ap-southeast-1.amazonaws.com/dev/mpx/v1'),
    ),
  );

  final didDocument = await didManager.getDidDocument();

  print(json.encode(didDocument.toJson()));
}
