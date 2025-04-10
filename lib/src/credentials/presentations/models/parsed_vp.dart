import 'verifiable_presentation.dart';

mixin ParsedVerifiablePresentation<SerializedType,
    T extends VerifiablePresentation> on VerifiablePresentation {
  SerializedType get serialized;
}
