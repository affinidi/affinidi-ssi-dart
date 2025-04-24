/// To be not be exposed from common package
enum SsiExceptionType {
  /// The Verifiable Credential Object Data Model is not supported
  unableToParseVerifiableCredential(code: 'unable_to_parse'),

  /// The Verifiable Presentation Object Data Model is not supported
  unableToParseVerifiablePresentation(code: 'unable_to_parse_presentation'),

  /// KeyPair missing private key
  keyPairMissingPrivateKey(code: 'key_pair_missing_private_key'),

  /// An error occurred while trying to resolve a did
  unableToResolveDid(code: 'unable_to_resolve_did'),

  /// Decryption of payload failed
  unableToDecrypt(code: 'unable_to_decrypt'),

  /// Encryption of payload failed
  unableToEncrypt(code: 'unable_to_encrypt'),

  /// The DID Document is not valid
  invalidDidDocument(code: 'invalid_did_document'),

  /// The JSON document is invalid
  invalidJson(code: 'invalid_json'),

  /// The did:peer or document is invalid
  invalidDidPeer(code: 'invalid_did_peer'),

  /// The did:web or document is invalid
  invalidDidWeb(code: 'invalid_did_web'),

  /// The did:key is invalid
  invalidDidKey(code: 'invalid_did_key'),

  /// The vc is invalid
  invalidVC(code: 'invalid_vc'),

  /// The encoding can't be parsed
  invalidEncoding(code: 'invalid_encoding'),

  /// The vc is expired
  expiredVC(code: 'expired_vc'),

  /// Integrity verification failed
  failedIntegrityVerification(code: 'integrity_verification_failed'),

  /// Unsupported signature scheme
  unsupportedSignatureScheme(code: 'unsupported_signature_scheme'),

  /// Unsupported signature scheme
  unsupportedEnvelopeVCOperation(code: 'unsupported_enveloped_vc_operation'),

  /// Invalid key type
  invalidKeyType(code: 'invalid_key_type'),

  /// Key not found in wallet or keystore
  keyNotFound(code: 'key_not_found'),

  /// Seed not found in wallet or keystore
  seedNotFound(code: 'seed_not_found'),

  /// An unknown error has occurred.
  other(code: 'other'),
  ;

  const SsiExceptionType({required this.code});

  final String code;
}
