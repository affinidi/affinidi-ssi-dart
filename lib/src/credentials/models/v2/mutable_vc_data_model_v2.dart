part of 'vc_data_model_v2.dart';

/// Default VC Data Model v1.2 context url
const String DMV2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

/// Represents a Verifiable Credential (VC) according to the W3C VC Data Model v1.1.
///
///  A Verifiable Credential (VC) is a digitally signed statement, issued by issuer
///
/// This class supports JSON serialization and deserialization for interoperability.
///  Example:
/// ```dart
/// MutableVcDataModelV2(
///  context: [
///    'https://www.w3.org/2018/credentials/v1',
///    'https://schema.affinidi.com/UserProfileV1-0.jsonld'
///  ],
///  id: Uri.parse('uuid:123456abcd'),
///  type: {'VerifiableCredential', 'UserProfile'},
///  credentialSubject: [
///    MutableCredentialSubject({
///      'Fname': 'Fname',
///      'Lname': 'Lame',
///      'Age': '22',
///      'Address': 'Eihhornstr'
///    })
///   ],
///  holder: MutableHolder.uri('did:example:1'),
///  credentialSchema: [
///    MutableCredentialSchema(
///        id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
///        type: 'JsonSchemaValidator2018')
///  ],
///  issuanceDate: DateTime.now(),
///  issuer: Issuer.uri(signer.did),
///);
/// ```
class MutableVcDataModelV2 {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v2'.
  List<String> context;

  /// The optional identifier for the Verifiable Credential.
  Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiableCredential'.
  Set<String> type;

  /// The schema(s) used to define the structure of the credential.
  List<MutableCredentialSchema> credentialSchema;

  /// The subject data contained in this credential.
  ///
  /// Example of a credential subject:
  /// ```
  /// {
  ///   "id": "did:example:123",
  ///   "name": "John Doe",
  /// }
  /// ```
  List<MutableCredentialSubject> credentialSubject;

  /// The entity that issued this credential.
  ///
  /// Typically a DID.
  MutableIssuer? issuer;

  /// The date and time at which the credential becomes effective.
  DateTime? validFrom;

  /// The date and time at which the credential becomes invalid.
  DateTime? validUntil;

  /// The cryptographic proof(s) created by the issuer.
  List<EmbeddedProof> proof;

  /// Credential status object to validate credentials revocation or suspension
  List<MutableCredentialStatusV2> credentialStatus;

  /// service(s) for how the credential can be refreshed.
  List<MutableRefreshServiceV2> refreshService;

  /// The terms of use for the Verifiable Credential.
  List<MutableTermsOfUse> termsOfUse;

  /// Evidence supporting the claims in the credential.
  List<MutableEvidence> evidence;

  /// Converts the [MutableVcDataModelV2] instance to a JSON representation.
  ///
  /// Returns a [Map<String, dynamic>] representing the JSON structure of the credential.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer?.toJson();
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

  /// Constructs a [MutableVcDataModelV2] instance.
  ///
  /// The constructor takes optional parameters to initialize the properties of the
  /// Verifiable Credential.  If a parameter is not provided, it defaults to an
  /// empty list, set, or null where appropriate.
  MutableVcDataModelV2({
    List<String>? context,
    this.id,
    List<MutableCredentialSchema>? credentialSchema,
    List<MutableCredentialSubject>? credentialSubject,
    this.issuer,
    Set<String>? type,
    this.validFrom,
    this.validUntil,
    List<EmbeddedProof>? proof,
    List<MutableCredentialStatusV2>? credentialStatus,
    List<MutableRefreshServiceV2>? refreshService,
    List<MutableTermsOfUse>? termsOfUse,
    List<MutableEvidence>? evidence,
  })  : context = context ?? [],
        credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? [],
        credentialStatus = credentialStatus ?? [],
        type = type ?? {},
        proof = proof ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];

  /// Constructs a [MutableVcDataModelV2] instance from a JSON object.
  ///
  /// The [input] parameter is a dynamic type
  /// representing the JSON structure of the Verifiable Credential.  This factory
  /// constructor parses the JSON and populates the properties of the
  /// [MutableVcDataModelV2] instance.
  factory MutableVcDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key);

    final id = getUri(json, _P.id.key);
    final type =
        getStringList(json, _P.type.key, allowSingleValue: true).toSet();

    final issuer = MutableIssuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<MutableCredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) =>
            MutableCredentialSubject.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<MutableCredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) =>
            MutableCredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final validFrom = getDateTime(json, _P.validFrom.key);

    final validUntil = getDateTime(json, _P.validUntil.key);

    final credentialStatus = parseListOrSingleItem<MutableCredentialStatusV2>(
        json,
        _P.credentialStatus.key,
        (item) =>
            MutableCredentialStatusV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final refreshService = parseListOrSingleItem<MutableRefreshServiceV2>(
        json,
        _P.refreshService.key,
        (item) =>
            MutableRefreshServiceV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<MutableTermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => MutableTermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<MutableEvidence>(
        json,
        _P.evidence.key,
        (item) => MutableEvidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return MutableVcDataModelV2(
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
}

typedef _P = VcDataModelV2Key;

/// Defines the keys used in the [MutableVcDataModelV2] class.
///
/// Each value represents a key that might be used in the JSON representation
/// of a Verifiable Credential.
enum VcDataModelV2Key {
  /// Key for the `@context` property, representing the JSON-LD context.
  context(key: '@context'),

  /// Key for the `proof` property, representing cryptographic proofs.
  proof,

  /// Key for the `issuer` property, representing the issuer of the credential.
  issuer,

  /// Key for the `credentialSchema` property, representing the schema.
  credentialSchema,

  /// Key for the `credentialSubject` property, representing the subject.
  credentialSubject,

  /// Key for the `id` property, representing the unique identifier.
  id,

  /// Key for the `type` property, representing the credential type.
  type,

  /// Key for the `validFrom` property, representing the starting of validation.
  validFrom,

  /// Key for the `validUntil` property, representing the expiry.
  validUntil,

  /// Key for the `credentialStatus` property, representing the credential status.
  credentialStatus,

  /// Key for the `refreshService` property, representing the refresh service.
  refreshService,

  /// Key for the `termsOfUse` property, representing the terms of use.
  termsOfUse,

  /// Key for the `evidence` property, representing the evidence.
  evidence,
  ;

  final String? _key;

  /// Returns the key string (custom or enum name).
  String get key => _key ?? name;

  const VcDataModelV2Key({String? key}) : _key = key;
}
