import '../../../ssi.dart';
import 'verifiable_credential.dart';

/// A verifiable credential that optionally includes a holder.
///
/// This interface extends [VerifiableCredential] to provide access to an optional
/// [Holder]. The holder represents the entity that possesses the credential, which
/// may differ from the credential subject(s).
///
/// Implementations of this interface should provide the [holder] property if the
/// credential explicitly defines a holder.
abstract interface class VerifiableCredentialWithHolder<SerializedType>
    implements VerifiableCredential {
  /// The original serialized representation of this credential.
  SerializedType get serialized;

  /// The optional holder of this credential.
  ///
  /// Returns null if the credential does not specify a holder.
  Holder? get holder;
}

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
