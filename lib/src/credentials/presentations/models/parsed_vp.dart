import 'verifiable_presentation.dart';

mixin ParsedVerifiablePresentation<SerializedType> on VerifiablePresentation {
  SerializedType get serialized;
}
