import 'package:ssi/src/did/universal_did_resolver.dart';

void main() async {
  // Create a resolver instance
  final resolver = UniversalDIDResolver();

  final didKeyDocument = await resolver.resolveDid(
    'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2',
  );
  print('Resolved did:key document: $didKeyDocument');

  final didPeerDocument = await resolver.resolveDid(
    'did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy',
  );
  print('Resolved did:peer document: $didPeerDocument');

  // Note: did:web resolution requires the target domain to host a valid DID document
  // at https://domain/.well-known/did.json
  // Example: final didWebDocument = await resolver.resolveDid('did:web:example.com');
  // print('Resolved did:web document: $didWebDocument');

  // Example with custom resolver address
  final customResolver = UniversalDIDResolver(
    resolverAddress: 'https://dev.uniresolver.io',
  );

  final externalDid = await customResolver.resolveDid('did:example:123');
  print('Resolved external DID: $externalDid');
}
