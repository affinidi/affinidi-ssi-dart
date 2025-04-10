import 'verifiable_credential.dart';

mixin ParsedVerifiableCredential<SerializedType, T extends VerifiableCredential>
    on VerifiableCredential {
  SerializedType get serialized;
}
