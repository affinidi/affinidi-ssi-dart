import '../models/verifiable_credential.dart';

abstract interface class VcDataModelParser {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  bool canParse(Object data);

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  VerifiableCredential parse(Object data);
}
