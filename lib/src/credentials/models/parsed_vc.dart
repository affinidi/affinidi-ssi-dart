import 'verifiable_credential.dart';

/// A verifiable credential that maintains its serialized representation.
///
/// This interface extends [VerifiableCredential] to provide access to the
/// original serialized form of the credential, which may be needed for
/// verification or transmission.
abstract interface class ParsedVerifiableCredential<SerializedType>
    implements VerifiableCredential {
  /// The original serialized representation of this credential.
  SerializedType get serialized;
}
