import 'package:ssi/src/credentials/models/parsed_vc.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/parsers/jwt_parser.dart';
import 'package:ssi/ssi.dart';

/// Allows creating a VcDataModel from a JWT token containing an VcDataModel version 1.1
/// Example: https://www.w3.org/TR/vc-data-model/#example-verifiable-credential-using-jwt-compact-serialization-non-normative
class JwtVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String> {
  final JWS _jws;

  JwtVcDataModelV1({
    required super.context,
    required super.id,
    super.credentialSchema,
    super.credentialSubject,
    required super.issuer,
    required super.type,
    super.issuanceDate,
    super.expirationDate,
    super.holder,
    super.proof,
    super.credentialStatus,
    required JWS jws,
  }) : _jws = jws;

  JwtVcDataModelV1.fromJws(JWS jws)
      : _jws = jws,
        // use parsing from VcDataModelV1
        super.fromJson(jwtToJson(jws.payload));

  @override
  String get serialized => _jws.serialized;

  static Map<String, dynamic> jwtToJson(Map<String, dynamic> payload) {
    Map<String, dynamic> json = payload['vc'];

    _jwtToJsonDate(payload, 'exp', json, _VC1.expirationDate.key);
    _jwtToJsonDate(payload, 'nbf', json, _VC1.issuanceDate.key);
    _jwtToJsonDynamic(payload, 'iss', json, _VC1.issuer.key);
    if (payload.containsKey('sub')) {
      json[_VC1.credentialSubject.key]['id'] = payload['sub'];
    }
    _jwtToJsonDynamic(payload, 'jti', json, _VC1.id.key);
    return json;
  }

  static (Map<String, dynamic> header, Map<String, dynamic> payload) vcToJwt(
    Map<String, dynamic> json,
    DidSigner signer,
  ) {
    Map<String, dynamic> payload = {};
    Map<String, dynamic> header = {
      'alg': signer.signatureScheme.jwtName,
      'kid': signer.keyId,
      'typ': 'JWT',
    };

    final exp = json.remove(_VC1.expirationDate.key);
    if (exp != null) {
      payload['exp'] =
          (DateTime.parse(exp).millisecondsSinceEpoch / 1000).floor();
    }

    final nbf = json.remove(_VC1.issuanceDate.key);
    if (nbf != null) {
      payload['nbf'] =
          (DateTime.parse(nbf).millisecondsSinceEpoch / 1000).floor();
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
