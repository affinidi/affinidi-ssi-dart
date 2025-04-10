import 'dart:convert';

import 'package:ssi/src/credentials/models/parsed_vc.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/util/base64_util.dart';
import 'package:ssi/ssi.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';

/// Allows creating a VcDataModel from a JWT token containing an VcDataModel version 1.1
/// Example: https://www.w3.org/TR/vc-data-model/#example-verifiable-credential-using-jwt-compact-serialization-non-normative
class JwtVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String> {
  String _serialized;

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
    required String serialized,
  }) : _serialized = serialized;

  JwtVcDataModelV1.fromJson(super.input)
      : _serialized = "",
        super.fromJson();

  /// Parse the input without verifying the signature
  factory JwtVcDataModelV1.parse(String jwtString) {
    final segments = jwtString.split('.');

    if (segments.length != 3) {
      throw SsiException(
        message: 'Invalid JWT',
        code: SsiExceptionType.invalidVC.code,
      );
    }

    final Map<String, dynamic> payload = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[1]),
      ),
    );

    Map<String, dynamic> json = _jwtToJson(payload);

    final result = JwtVcDataModelV1.fromJson(json);
    result._serialized = jwtString;

    return result;
  }

  /// Check that the serialized CV passes the format's integrity checks
  Future<bool> get hasIntegrity async {
    final segments = _serialized.split('.');

    if (segments.length != 3) {
      throw SsiException(
        message: 'Invalid JWT',
        code: SsiExceptionType.invalidVC.code,
      );
    }

    final encodedHeader = segments[0];
    final encodedPayload = segments[1];
    final encodedSignature = segments[2];

    final decodedHeader = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(encodedHeader),
      ),
    );

    final toSign = ascii.encode('$encodedHeader.$encodedPayload');

    Uri did = Uri.parse(decodedHeader['kid']).removeFragment();

    //TODO(cm) add discovery
    final algorithm = SignatureScheme.ecdsa_secp256k1_sha256;

    final verifier = await DidVerifier.create(
      algorithm: algorithm,
      kid: decodedHeader['kid'],
      issuerDid: did.toString(),
    );

    return verifier.verify(toSign, base64UrlNoPadDecode(encodedSignature));
  }

  static Future<String> encode(
    VerifiableCredential dataModel,
    DidSigner signer,
  ) async {
    final vcdm1 = dataModel as VcDataModelV1;

    final (header, payload) = _vcToJwt(vcdm1.toJson(), signer);

    final encodedHeader = base64UrlNoPadEncode(
      utf8.encode(jsonEncode(header)),
    );
    final encodedPayload = base64UrlNoPadEncode(
      utf8.encode(jsonEncode(payload)),
    );

    final toSign = ascii.encode('$encodedHeader.$encodedPayload');

    final signature = base64UrlNoPadEncode(
      await signer.sign(toSign),
    );

    return '$encodedHeader.$encodedPayload.$signature';
  }

  @override
  String get serialized => _serialized;
}

Map<String, dynamic> _jwtToJson(Map<String, dynamic> payload) {
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

(Map<String, dynamic> header, Map<String, dynamic> payload) _vcToJwt(
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

void _jwtToJsonDynamic(
  Map<String, dynamic> payload,
  String payloadField,
  Map<String, dynamic> json,
  String jsonField,
) {
  if (payload[payloadField] != null) {
    json[jsonField] = payload[payloadField];
  }
}

void _jwtToJsonDate(
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

typedef _VC1 = VcDataModelV1Key;
