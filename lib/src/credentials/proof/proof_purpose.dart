/// Defines the purpose for which a cryptographic proof can be used.
///
/// Each purpose indicates a specific type of usage that is allowed
/// for a proof within the verifiable credentials ecosystem.
enum ProofPurpose {
  /// Indicates that a proof is only to be used for authentication protocols.
  ///
  /// This purpose is used when the proof serves to authenticate an entity's identity.
  authentication('authentication'),

  /// Indicates that a proof is used for making assertions.
  ///
  /// This purpose is typically used when signing verifiable credentials.
  assertionMethod('assertionMethod'),

  /// Indicates that a proof is used for key agreement protocols.
  ///
  /// This includes protocols such as Elliptic Curve Diffie-Hellman key agreement
  /// used by popular encryption libraries.
  keyAgreement('keyAgreement'),

  /// Indicates that a proof is used for delegating capabilities.
  ///
  /// See the Authorization Capabilities ZCAP specification for more detail.
  capabilityDelegation('capabilityDelegation'),

  /// Indicates that a proof is used for invoking capabilities.
  ///
  /// See the Authorization Capabilities ZCAP specification for more detail.
  capabilityInvocation('capabilityInvocation');

  /// The string value of this proof purpose.
  final String value;

  /// Creates a new [ProofPurpose] enum instance.
  const ProofPurpose(this.value);
}
