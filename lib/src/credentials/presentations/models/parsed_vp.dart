import 'verifiable_presentation.dart';

/// An interface representing a parsed Verifiable Presentation (VP) with access
/// to its original serialized representation.
abstract interface class ParsedVerifiablePresentation<SerializedType>
    implements VerifiablePresentation {
  /// Returns the original serialized form of the presentation.
  SerializedType get serialized;
}
