class Proof {
  final String type;
  final DateTime? created;
  final String? verificationMethod;
  final String? proofPurpose;
  final String? challenge;
  final String? domain;
  final String? proofValue;
  final Map<String, dynamic>? jwk;
  final String? nonce;
  final Map<String, dynamic>? additionalProperties;

  Proof({
    required this.type,
    this.created,
    this.verificationMethod,
    this.proofPurpose,
    this.challenge,
    this.domain,
    this.proofValue,
    this.jwk,
    this.nonce,
    this.additionalProperties,
  });

  factory Proof.fromJson(Map<String, dynamic> json) {
    final type = json['type'] as String;
    final created = json['created'] != null
        ? DateTime.parse(json['created'] as String)
        : null;
    final verificationMethod = json['verificationMethod'] as String?;
    final proofPurpose = json['proofPurpose'] as String?;
    final challenge = json['challenge'] as String?;
    final domain = json['domain'] as String?;
    final proofValue = json['proofValue'] as String?;
    final nonce = json['nonce'] as String?;
    final jwk = json['jwk'] != null
        ? Map<String, dynamic>.from(json['jwk'] as Map<String, dynamic>)
        : null;
    final additionalProps = Map<String, dynamic>.from(json);
    [
      'type',
      'created',
      'verificationMethod',
      'proofPurpose',
      'challenge',
      'domain',
      'proofValue',
      'jwk',
      'nonce',
    ].forEach(additionalProps.remove);

    return Proof(
      type: type,
      created: created,
      verificationMethod: verificationMethod,
      proofPurpose: proofPurpose,
      challenge: challenge,
      domain: domain,
      proofValue: proofValue,
      jwk: jwk,
      nonce: nonce,
      additionalProperties: additionalProps.isNotEmpty ? additionalProps : null,
    );
  }

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'type': type,
    };

    if (created != null) {
      json['created'] = created!.toIso8601String();
    }

    if (verificationMethod != null) {
      json['verificationMethod'] = verificationMethod;
    }

    if (proofPurpose != null) {
      json['proofPurpose'] = proofPurpose;
    }

    if (challenge != null) {
      json['challenge'] = challenge;
    }

    if (domain != null) {
      json['domain'] = domain;
    }

    if (proofValue != null) {
      json['proofValue'] = proofValue;
    }

    if (jwk != null) {
      json['jwk'] = jwk;
    }

    if (nonce != null) {
      json['nonce'] = nonce;
    }

    if (additionalProperties != null) {
      json.addAll(additionalProperties!);
    }

    return json;
  }

  @override
  String toString() =>
      'Proof{type: $type, created: $created, verificationMethod: $verificationMethod}';
}
