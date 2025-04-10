import 'verifiable_credential.dart';

abstract class ParsedVerifiableCredential<SerializedType>
    implements VerifiableCredential {
  SerializedType get serialized;
}
