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

  /// The date and time when this proof was created.
  final DateTime? created;

  /// The verification method used for this proof.
  final String? verificationMethod;

  /// The purpose of this proof.
  final String? proofPurpose;

  /// The cryptosuite that was used to create this proof.
  final String? cryptosuite;

  /// The date and time when this proof expires.
  final DateTime? expires;

  /// The domains this proof is bound to.
  /// Can be a single string or a list of strings.
  final List<String>? domain;

  /// A challenge to prevent replay attacks.
  final String? challenge;

  /// The cryptographic proof value.
  final String? proofValue;

  /// References to previous proofs.
  final List<String>? previousProof;

  /// A nonce used in the proof generation.
  final String? nonce;

  /// JWK property (from Proof).
  final Map<String, dynamic>? jwk;

  /// Additional properties (from Proof).
  final Map<String, dynamic>? additionalProperties;

  /// Constructs an [EmbeddedProof].
  EmbeddedProof({
    this.id,
    required this.type,
    this.created,
    this.verificationMethod,
    this.proofPurpose,
    this.cryptosuite,
    this.expires,
    this.domain,
    this.challenge,
    this.proofValue,
    this.previousProof,
    this.nonce,
    this.jwk,
    this.additionalProperties,
  });

  /// Converts this proof to a JSON-serializable map.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'type': type,
    };

    if (id != null) {
      json['id'] = id.toString();
    }
    if (created != null) {
      json['created'] = created!.toIso8601String();
    }
    if (verificationMethod != null) {
      json['verificationMethod'] = verificationMethod;
    }
    if (proofPurpose != null) {
      json['proofPurpose'] = proofPurpose;
    }
    if (cryptosuite != null) {
      json['cryptosuite'] = cryptosuite;
    }
    if (expires != null) {
      json['expires'] = expires!.toIso8601String();
    }
    if (domain != null) {
      if (domain!.length == 1) {
        json['domain'] = domain!.first;
      } else if (domain!.isNotEmpty) {
        json['domain'] = domain;
      }
    }
    if (challenge != null) {
      json['challenge'] = challenge;
    }
    if (proofValue != null) {
      json['proofValue'] = proofValue;
    }
    if (previousProof != null && previousProof!.isNotEmpty) {
      if (previousProof!.length == 1) {
        json['previousProof'] = previousProof!.first;
      } else {
        json['previousProof'] = previousProof;
      }
    }
    if (nonce != null) {
      json['nonce'] = nonce;
    }
    if (jwk != null) {
      json['jwk'] = jwk;
    }
    if (additionalProperties != null) {
      json.addAll(additionalProperties!);
    }

    return json;
  }

  /// Creates an [EmbeddedProof] from JSON data.
  factory EmbeddedProof.fromJson(Map<String, dynamic> input) {
    final additionalProps = Map<String, dynamic>.from(input);
    [
      'id',
      'type',
      'created',
      'verificationMethod',
      'proofPurpose',
      'cryptosuite',
      'expires',
      'domain',
      'challenge',
      'proofValue',
      'previousProof',
      'nonce',
      'jwk',
    ].forEach(additionalProps.remove);

    Uri? id;
    if (input['id'] != null) {
      try {
        id = Uri.parse(input['id'].toString());
      } catch (_) {
        id = null;
      }
    }

    List<String>? domain;
    if (input['domain'] != null) {
      if (input['domain'] is String) {
        domain = [input['domain'] as String];
      } else if (input['domain'] is List) {
        domain = (input['domain'] as List).map((e) => e.toString()).toList();
      }
    }

    List<String>? previousProof;
    if (input['previousProof'] != null) {
      if (input['previousProof'] is String) {
        previousProof = [input['previousProof'] as String];
      } else if (input['previousProof'] is List) {
        previousProof =
            (input['previousProof'] as List).map((e) => e.toString()).toList();
      }
    }

    return EmbeddedProof(
      id: id,
      type: input['type'] as String,
      created: input['created'] != null
          ? DateTime.tryParse(input['created'].toString())
          : null,
      verificationMethod: input['verificationMethod'] as String?,
      proofPurpose: input['proofPurpose'] as String?,
      cryptosuite: input['cryptosuite'] as String?,
      expires: input['expires'] != null
          ? DateTime.tryParse(input['expires'].toString())
          : null,
      domain: domain,
      challenge: input['challenge'] as String?,
      proofValue: input['proofValue'] as String?,
      previousProof: previousProof,
      nonce: input['nonce'] as String?,
      jwk: input['jwk'] != null
          ? Map<String, dynamic>.from(input['jwk'] as Map)
          : null,
      additionalProperties: additionalProps.isNotEmpty ? additionalProps : null,
    );
  }

  @override
  String toString() =>
      'EmbeddedProof{type: $type, created: $created, verificationMethod: $verificationMethod}';
}
