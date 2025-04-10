import 'package:ssi/src/credentials/models/verifiable_credential.dart';

mixin ParsedVerifiableCredential<SerializedType> on VerifiableCredential {
  SerializedType get serialized;
}
