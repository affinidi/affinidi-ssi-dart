import 'package:jwt_decoder/jwt_decoder.dart';

import '../credential_schema.dart';
import '../verifiable_credential.dart';

/// Allows creating a VcDataModel from a JWT token containing an VcDataModel version 1.1
/// Example: https://www.w3.org/TR/vc-data-model/#example-verifiable-credential-using-jwt-compact-serialization-non-normative
class JwtVcDataModelV1 implements VerifiableCredential {
  JwtVcDataModelV1(String jwtString)
      : _jsonDataModel = Map.unmodifiable(JwtDecoder.decode(jwtString)),
        _rawData = jwtString;

  final Map<String, dynamic> _jsonDataModel;

  final dynamic _rawData;

  @override
  dynamic get rawData => _rawData;

  @override
  DateTime? get validUntil =>
      _jsonDataModel.containsKey(_JwtVcDataModelV11Key.validUntil.key)
          ? _fromSecondsSinceEpoch(
              _jsonDataModel[_JwtVcDataModelV11Key.validUntil.key] as int,
              isUtc: true)
          : null;

  @override
  String get issuer =>
      _jsonDataModel[_JwtVcDataModelV11Key.issuer.key] as String;

  @override
  List<CredentialSchema> get credentialSchema =>
      (_jsonDataModel[_JwtVcDataModelV11Key.verifiableCredential.key] as Map<
                  String,
                  dynamic>?)?[_JwtVcDataModelV11Key.credentialSchema.key] !=
              null
          ? [
              CredentialSchema.fromJson((_jsonDataModel[_JwtVcDataModelV11Key
                          .verifiableCredential.key] as Map<String, dynamic>)[
                      _JwtVcDataModelV11Key.credentialSchema.key]
                  as Map<String, dynamic>)
            ]
          : [];

  @override
  Map<String, dynamic> get credentialSubject =>
      (_jsonDataModel[_JwtVcDataModelV11Key.verifiableCredential.key] as Map<
              String, dynamic>)[_JwtVcDataModelV11Key.credentialSubject.key]
          as Map<String, dynamic>;

  @override
  String get id => _jsonDataModel[_JwtVcDataModelV11Key.id.key] as String;

  @override
  DateTime get validFrom => _fromSecondsSinceEpoch(
      _jsonDataModel[_JwtVcDataModelV11Key.issuanceDate.key] as int,
      isUtc: true);

  @override
  List<String> get type => List<String>.from(
      (_jsonDataModel[_JwtVcDataModelV11Key.verifiableCredential.key]
          as Map<String, dynamic>)[_JwtVcDataModelV11Key.type.key] as List);

  DateTime _fromSecondsSinceEpoch(int secondsSinceEpoch,
          {bool isUtc = false}) =>
      DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000,
          isUtc: isUtc);

  @override
  dynamic toJson() => _jsonDataModel;

  @override
  // TODO: implement context
  List<String> get context => throw UnimplementedError();
}

enum _JwtVcDataModelV11Key {
  verifiableCredential('vc'),
  validUntil('exp'),
  issuer('iss'),
  credentialSchema('credentialSchema'),
  id('jti'),
  issuanceDate('nbf'),
  type('type'),
  credentialSubject('credentialSubject'),
  ;

  const _JwtVcDataModelV11Key(this.key);

  final String key;
}
