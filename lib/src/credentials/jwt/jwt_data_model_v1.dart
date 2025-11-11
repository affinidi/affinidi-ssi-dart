part of 'jwt_dm_v1_suite.dart';

/// Allows creating a VcDataModel from a JWT token containing an VcDataModel version 1.1
/// Example: https://www.w3.org/TR/vc-data-model/#example-verifiable-credential-using-jwt-compact-serialization-non-normative
class JwtVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String> {
  /// The decoded JWS (JSON Web Signature) object.
  final Jws jws;

  /// Creates a [JwtVcDataModelV1] instance from a [Jws].
  JwtVcDataModelV1.fromJws(this.jws)
      : super.clone(VcDataModelV1.fromJson(jwtToJson(jws.payload)));

  @override
  String get serialized => jws.serialized;

  @override
  Map<String, dynamic> toJson() {
    return jws.payload['vc'] as Map<String, dynamic>;
  }

  /// Converts a VC JSON object to a pair of JWT header and payload.
  ///
  /// This prepares the data for signing as a JWT.
  static (Map<String, dynamic> header, Map<String, dynamic> payload) vcToJws(
    Map<String, dynamic> json,
    DidSigner signer,
  ) {
    final payload = <String, dynamic>{};
    final header = <String, dynamic>{
      'alg': signer.signatureScheme.alg,
      'kid': signer.keyId,
      'typ': 'JWT',
    };

    final exp = json.remove(_VC1.expirationDate.key);
    if (exp != null) {
      payload['exp'] =
          (DateTime.parse(exp as String).millisecondsSinceEpoch / 1000).floor();
    }

    final nbf = json.remove(_VC1.validFrom.key);
    if (nbf != null) {
      payload['nbf'] =
          (DateTime.parse(nbf as String).millisecondsSinceEpoch / 1000).floor();
    }

    final iat = json.remove(_VC1.issuanceDate.key);
    if (iat != null) {
      payload['iat'] =
          (DateTime.parse(iat as String).millisecondsSinceEpoch / 1000).floor();
    }

    payload['iss'] = json.remove(_VC1.issuer.key);

    final id = json.remove(_VC1.id.key);
    if (id != null) {
      payload['jti'] = id;
    }

    var credentialSubject = json['credentialSubject'];
    if (credentialSubject is Map && credentialSubject.containsKey('id')) {
      payload['sub'] = credentialSubject['id'];
    }

    payload['vc'] = json;

    return (header, payload);
  }

  /// Converts a JWT payload back into a VC JSON object.
  static Map<String, dynamic> jwtToJson(Map<String, dynamic> payload) {
    final json = payload['vc'] as Map<String, dynamic>;

    _jwtToJsonDate(payload, 'exp', json, _VC1.expirationDate.key);
    _jwtToJsonDate(payload, 'nbf', json, _VC1.validFrom.key);
    _jwtToJsonDate(payload, 'iat', json, _VC1.issuanceDate.key);
    _jwtToJsonDynamic(payload, 'iss', json, _VC1.issuer.key);
    if (payload.containsKey('sub')) {
      (json[_VC1.credentialSubject.key] as Map<String, dynamic>)['id'] =
          payload['sub'];
    }
    _jwtToJsonDynamic(payload, 'jti', json, _VC1.id.key);
    return json;
  }

  static void _jwtToJsonDynamic(
    Map<String, dynamic> payload,
    String payloadField,
    Map<String, dynamic> json,
    String jsonField,
  ) {
    if (payload[payloadField] != null) {
      json[jsonField] = payload[payloadField];
    }
  }

  static void _jwtToJsonDate(
    Map<String, dynamic> payload,
    String payloadField,
    Map<String, dynamic> json,
    String jsonField,
  ) {
    if (payload[payloadField] != null && payload[payloadField] is int) {
      json[jsonField] = DateTime.fromMillisecondsSinceEpoch(
        (payload[payloadField] as int) * 1000,
        isUtc: true,
      ).toIso8601String();
    }
  }
}

typedef _VC1 = VcDataModelV1Key;
