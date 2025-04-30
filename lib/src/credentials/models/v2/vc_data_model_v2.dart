import 'dart:collection';

import '../../../../ssi.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../field_types/credential_status/v2.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v2.dart';
import '../field_types/terms_of_use.dart';

part './mutable_vc_data_model_v2.dart';

/// Represents a Verifiable Credential (VC) according to the W3C VC Data Model v1.2.
///
///  A Verifiable Credential (VC) is a digitally signed statement, issued by issuer
///
/// This class supports JSON serialization and deserialization for interoperability.
///  Example:
/// ```dart
/// VcDataModelV2(
///  context: [
///    'https://www.w3.org/2018/credentials/v1',
///    'https://schema.affinidi.com/UserProfileV1-0.jsonld'
///  ],
///  id: Uri.parse('uuid:123456abcd'),
///  type: {'VerifiableCredential', 'UserProfile'},
///  credentialSubject: [
///    CredentialSubject({
///      'Fname': 'Fname',
///      'Lname': 'Lame',
///      'Age': '22',
///      'Address': 'Eihhornstr'
///    })
///   ],
///  holder: Holder.uri('did:example:1'),
///  credentialSchema: [
///    CredentialSchema(
///        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
///        type: 'JsonSchemaValidator2018')
///  ],
///  issuanceDate: DateTime.now(),
///  issuer: Issuer.uri(signer.did),
///);
/// ```
class VcDataModelV2 implements VerifiableCredential {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v2'.
  @override
  final UnmodifiableListView<String> context;

  /// The optional identifier for the Verifiable Credential.
  @override
  final Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiableCredential'.
  @override
  final UnmodifiableSetView<String> type;

  /// The entity that issued this credential.
  ///
  /// Typically a DID.
  @override
  final Issuer issuer;

  /// The subject data contained in this credential.
  ///
  /// Example of a credential subject:
  /// ```
  /// {
  ///   "id": "did:example:123",
  ///   "name": "John Doe",
  /// }
  /// ```
  @override
  final UnmodifiableListView<CredentialSubject> credentialSubject;

  /// The cryptographic proof(s) created by the issuer.
  @override
  final UnmodifiableListView<EmbeddedProof> proof;

  /// The schema(s) used to define the structure of the credential.
  @override
  final UnmodifiableListView<CredentialSchema> credentialSchema;

  /// The date and time at which the credential becomes effective.
  @override
  final DateTime? validFrom;

  /// The date and time at which the credential becomes invalid.
  @override
  final DateTime? validUntil;

  /// Credential status object to validate credentials revocation or suspension
  final UnmodifiableListView<CredentialStatusV2> credentialStatus;

  /// service(s) for how the credential can be refreshed.
  final UnmodifiableListView<RefreshServiceV2> refreshService;

  /// The terms of use for the Verifiable Credential.
  @override
  final UnmodifiableListView<TermsOfUse> termsOfUse;

  /// Evidence supporting the claims in the credential.
  final UnmodifiableListView<Evidence> evidence;

  /// Converts the [VcDataModelV2] instance to a JSON representation.
  ///
  /// Returns a [Map<String, dynamic>] representing the JSON structure of the credential.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer.toJson();
    json[_P.type.key] = type.toList();
    json[_P.id.key] = id?.toString();
    json[_P.credentialSchema.key] = encodeListToSingleOrArray(credentialSchema);
    json[_P.validFrom.key] = validFrom?.toIso8601String();
    json[_P.validUntil.key] = validUntil?.toIso8601String();
    json[_P.credentialSubject.key] =
        encodeListToSingleOrArray(credentialSubject);
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.credentialStatus.key] = encodeListToSingleOrArray(credentialStatus);
    json[_P.refreshService.key] = encodeListToSingleOrArray(refreshService);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.evidence.key] = encodeListToSingleOrArray(evidence);

    return cleanEmpty(json);
  }

  /// Validates the essential Verifiable Credential properties (`context`, `type`, `credentialSubject`).
  ///
  /// Ensures [context] is not empty and starts with [DMV2ContextUrl],
  /// and the [type] is not empty.
  /// and the [credentialSubject] is not empty
  ///
  /// Throws [SsiException] if validation fails. Returns `true` if valid.
  bool validate() {
    if (context.isEmpty) {
      throw SsiException(
        message: '`${_P.context.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (context.first != DMV2ContextUrl) {
      throw SsiException(
        message:
            'The first URI of `${_P.context.key}` property should always be $DMV2ContextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (type.isEmpty) {
      throw SsiException(
        message: '`${_P.type.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (credentialSubject.isEmpty) {
      throw SsiException(
        message: '`${_P.credentialSubject.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return true;
  }

  /// Creates a [VcDataModelV2] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [id] is otptionla identifier (optional)
  /// the [credentialSubject] is contain claims of subject (required)
  /// The [issuer] is issuer of this VC (required)
  /// The [type] is an array that must include 'VerifiableCredential' (requires)
  /// The [validFrom] is date and time at  which the credential becomes effective (optional)
  /// The [validUntil] is date and time  at which the credential becomes invalid (optional)
  /// The [credentialSchema] is credential schema against VC is issued (optional)
  /// The [proof] is a cryptographic proof (optional)
  /// The [credentialStatus] is a list of Credential Status object (optional)
  /// The [refreshService] is a list of refresh service (optional)
  /// The [termsOfUse] is a list of terms of use (optional)
  /// The [evidence] is a list of evidence (optional)
  VcDataModelV2({
    required List<String> context,
    this.id,
    required List<CredentialSubject> credentialSubject,
    required this.issuer,
    required Set<String> type,
    this.validFrom,
    this.validUntil,
    List<CredentialSchema>? credentialSchema,
    List<EmbeddedProof>? proof,
    List<CredentialStatusV2>? credentialStatus,
    List<RefreshServiceV2>? refreshService,
    List<TermsOfUse>? termsOfUse,
    List<Evidence>? evidence,
  })  : context = UnmodifiableListView(context),
        credentialSubject = UnmodifiableListView(credentialSubject),
        type = UnmodifiableSetView(type),
        proof = UnmodifiableListView(proof ?? []),
        credentialSchema = UnmodifiableListView(credentialSchema ?? []),
        credentialStatus = UnmodifiableListView(credentialStatus ?? []),
        refreshService = UnmodifiableListView(refreshService ?? []),
        termsOfUse = UnmodifiableListView(termsOfUse ?? []),
        evidence = UnmodifiableListView(evidence ?? []) {
    validate();
  }

  /// Creates a [VcDataModelV2] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory VcDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);

    final id = getUri(json, _P.id.key);
    final type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    ).toSet();

    final issuer = Issuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<CredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) => CredentialSubject.fromJson(item as Map<String, dynamic>),
        mandatory: true,
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<CredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) => CredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final validFrom = getDateTime(json, _P.validFrom.key);

    final validUntil = getDateTime(json, _P.validUntil.key);

    final credentialStatus = parseListOrSingleItem<CredentialStatusV2>(
        json,
        _P.credentialStatus.key,
        (item) => CredentialStatusV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final refreshService = parseListOrSingleItem<RefreshServiceV2>(
        json,
        _P.refreshService.key,
        (item) => RefreshServiceV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<TermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => TermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<Evidence>(json, _P.evidence.key,
        (item) => Evidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return VcDataModelV2(
        context: context,
        id: id,
        credentialSubject: credentialSubject,
        issuer: issuer,
        type: type,
        validFrom: validFrom,
        credentialSchema: credentialSchema,
        validUntil: validUntil,
        proof: proof,
        credentialStatus: credentialStatus,
        refreshService: refreshService,
        termsOfUse: termsOfUse,
        evidence: evidence);
  }

  /// Creates a new [VcDataModelV2] instance as a deep copy of the provided [input].
  ///
  /// This constructor initializes a new object with the same values as the
  /// properties of the [input] `VcDataModelV2` instance.
  VcDataModelV2.clone(VcDataModelV2 input)
      : this(
            context: input.context,
            id: input.id,
            credentialSubject: input.credentialSubject,
            issuer: input.issuer,
            type: input.type,
            validFrom: input.validFrom,
            credentialSchema: input.credentialSchema,
            validUntil: input.validUntil,
            proof: input.proof,
            credentialStatus: input.credentialStatus,
            refreshService: input.refreshService,
            termsOfUse: input.termsOfUse,
            evidence: input.evidence);

  /// Factory constructor to create a `VcDataModelV2` instance from a mutable `MutableVcDataModelV2`
  ///
  /// Example:
  /// ```dart
  /// MutableVcDataModelV2 mutableData = MutableVcDataModelV2(
  ///   id: 'some-unique-id',
  ///   type: ['VerifiableCredential', 'ExampleCredential'],
  ///   issuer: 'did:example:issuer',
  ///   issuanceDate: DateTime.now(),
  ///   credentialSubject: {'name': 'John Doe'},
  /// );
  ///
  /// VcDataModelV2 immutableData = VcDataModelV2.fromMutable(mutableData);
  /// ```
  factory VcDataModelV2.fromMutable(MutableVcDataModelV2 data) =>
      VcDataModelV2.fromJson(data.toJson());
}
