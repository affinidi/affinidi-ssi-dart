import 'package:ssi/src/credentials/models/verifiable_credential.dart';

mixin ParsedVerifiableCredential<SerializedType,
    VDM extends VerifiableCredential> on VerifiableCredential {
  SerializedType get serialized;
}
