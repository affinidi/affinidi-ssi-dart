import '../../util/json_util.dart';

/// Immutable model of an embedded proof conformant to [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/#proofs)
class EmbeddedProof {
  final Uri? id;
  final String type;
  final String proofPurpose;
  final String? verificationMethod;
  final String? cryptosuite;
  final DateTime? created;
  final DateTime? expires;
  final List<String> domain;
  final String? challenge;
  final String? proofValue;
  final List<String> previousProof;
  final String? nonce;

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
