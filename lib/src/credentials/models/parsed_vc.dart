import '../../../ssi.dart';

abstract interface class ParsedVerifiableCredential<SerializedType>
    implements VerifiableCredential {
  SerializedType get serialized;
}
