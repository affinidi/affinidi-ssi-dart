import 'verifiable_presentation.dart';

abstract interface class ParsedVerifiablePresentation<SerializedType>
    implements VerifiablePresentation {
  SerializedType get serialized;
}
