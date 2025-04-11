/// What the proof can be used for
enum ProofPurpose {
  /// Indicates that a given proof is only to be used for the purposes of an authentication protocol.
  authentication('authentication'),

  /// Indicates that a proof can only be used for making assertions, for example signing a verifiable credential.
  assertionMethod('assertionMethod'),

  /// Indicates that a proof is used for for key agreement protocols, such as Elliptic Curve Diffie Hellman key agreement used by popular encryption libraries.
  keyAgreement('keyAgreement'),

  /// Indicates that the proof can only be used for delegating capabilities. See the Authorization Capabilities ZCAP specification for more detail.
  capabilityDelegation('capabilityDelegation'),

  /// Indicates that the proof can only be used for invoking capabilities. See the Authorization Capabilities ZCAP specification for more detail.
  capabilityInvocation('capabilityInvocation');

  final String value;

  const ProofPurpose(this.value);
}
