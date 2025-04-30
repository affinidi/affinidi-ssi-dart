import 'package:ssi/src/did/universal_did_resolver.dart';

void main() async {
  final didKeyDocument = await UniversalDIDResolver.resolve(
    'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2',
  );
  print('Resolved did:key document: $didKeyDocument');

  final didPeerDocument = await UniversalDIDResolver.resolve(
    'did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy',
  );
  print('Resolved did:peer document: $didPeerDocument');

  final didWebDocument = await UniversalDIDResolver.resolve(
    'did:web:demo.spruceid.com',
  );
  print('Resolved did:web document: $didWebDocument');
}
