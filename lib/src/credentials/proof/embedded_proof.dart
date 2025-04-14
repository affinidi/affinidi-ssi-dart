import '../../util/json_util.dart';

/// Immutable model of an embedded proof conformant to the W3C Verifiable Credential Data Integrity 1.0 specification.
///
/// This class represents a cryptographic proof that can be embedded within credentials and presentations
/// to provide data integrity and authenticity verification.
///
/// See the W3C specification at: https://www.w3.org/TR/vc-data-integrity/#proofs
class EmbeddedProof {
  /// The optional identifier for this proof.
  final Uri? id;

  /// The type of cryptographic signature used.
  final String type;

  /// The purpose of this proof.
  final String proofPurpose;

  /// The verification method used for this proof.
  final String? verificationMethod;

  /// The cryptosuite that was used to create this proof.
  final String? cryptosuite;

  /// The date and time when this proof was created.
  final DateTime? created;

  /// The date and time when this proof expires.
  final DateTime? expires;

  /// The domains this proof is bound to.
  final List<String> domain;

  /// A challenge to prevent replay attacks.
  final String? challenge;

  /// The cryptographic proof value.
  final String? proofValue;

  /// References to previous proofs.
  final List<String> previousProof;

  /// A nonce used in the proof generation.
  final String? nonce;

  /// Creates an [EmbeddedProof] instance.
  ///
  /// The [type] specifies the cryptographic proof type.
  /// The [proofPurpose] indicates the reason this proof was created.
  EmbeddedProof({
    this.id,
    required this.type,
    required this.proofPurpose,
    this.verificationMethod,
    this.cryptosuite,
    this.created,
    this.expires,
    List<String>? domain,
    this.challenge,
    this.proofValue,
    List<String>? previousProof,
    this.nonce,
  })  : domain = domain ?? List.empty(),
        previousProof = previousProof ?? List.empty();

  /// Converts this proof to a JSON-serializable map.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    addOptional(json, 'id', id);
    json['type'] = type;
    json['proofPurpose'] = proofPurpose;
    addOptional(json, 'verificationMethod', verificationMethod);
    addOptional(json, 'cryptosuite', cryptosuite);
    addOptional(json, 'created', created?.toIso8601String());
    addOptional(json, 'expires', expires?.toIso8601String());
    addList(json, 'domain', domain, allowSingleValue: true);
    addOptional(json, 'challenge', challenge);
    addOptional(json, 'proofValue', proofValue);
    addList(json, 'previousProof', previousProof, allowSingleValue: true);
    addOptional(json, 'nonce', nonce);

    return json;
  }

  /// Creates an [EmbeddedProof] from JSON data.
  ///
  /// The [input] must contain the required fields 'type' and 'proofPurpose'.
  EmbeddedProof.fromJson(Map<String, dynamic> input)
      : id = input['id'] != null
            ? Uri.parse(getMandatoryString(input, 'id'))
            : null,
        type = getMandatoryString(input, 'type'),
        proofPurpose = getMandatoryString(input, 'proofPurpose'),
        verificationMethod = getString(input, 'verificationMethod'),
        cryptosuite = getString(input, 'cryptosuite'),
        created = getDateTime(input, 'created'),
        expires = getDateTime(input, 'expires'),
        domain = List.unmodifiable(
          getStringList(input, 'domain', allowSingleValue: true),
        ),
        challenge = getString(input, 'challenge'),
        proofValue = getString(input, 'proofValue'),
        previousProof = List.unmodifiable(
          getStringList(input, 'previousProof', allowSingleValue: true),
        ),
        nonce = getString(input, 'nonce');
}
