/// Defines the purpose of a verification method within a DID Document.
enum VerificationRelationship {
  /// For proving control of a DID.
  authentication,

  /// For stating claims. Often the same as authentication.
  assertionMethod,

  /// For invoking granular capabilities (e.g., ZCaps).
  capabilityInvocation,

  /// For delegating capabilities.
  capabilityDelegation,

  /// For establishing encrypted communication channels.
  keyAgreement,
}
