import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../json_ld/context.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/p256_key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../wallet/wallet.dart';
import 'did_document/index.dart';
import 'public_key_utils.dart';

/// The URL for the Cheqd DID resolver service.
String cheqdResolverUrl = 'https://resolver.cheqd.net/1.0/identifiers/';

/// The base URL for the Cheqd DID registrar service (running locally).
String cheqdRegistrarUrl = 'http://localhost:3000';

/// TRQP-Compliant Authorization Query Response Structure
class AuthorizationQueryResponse {
  /// Entity ID
  final String entityId;

  /// TRQP Authorization status
  final bool authorized;

  /// TRQP Authorization status detail
  final String message;

  /// Assertion ID (Role)
  final DIDAccreditationTypes? assertionId;

  /// The chain of issuers encountered
  final List<String>? accreditorDids;

  /// The final root authorization DID
  final String? authorityId;

  /// Converted Response
  AuthorizationQueryResponse({
    required this.entityId,
    required this.authorized,
    required this.message,
    this.accreditorDids,
    this.authorityId,
    this.assertionId,
  });
}

/// Represents a Authorization Query Request as defined by the Trust Registry Query Protocol (TRQP).
class AuthorizationQueryRequest {
  /// A unique identifier for the entity whose recognition status is being evaluated (e.g., a DID).
  final String entityId;

  /// A uri pointing to the authorization proof of the entity
  final String uri;

  /// A unique identifier for the authority making the recognition assertion (e.g., an Root DID).
  final String? authorityId;

  /// A unique identifier for the specific authorization type being queried
  final DIDAccreditationTypes? assertionId;

  /// Auxiliary parameters that influence evaluation, such as a timestamp. Optional.
  final Map<String, dynamic>? context;

  /// List of schemas the entity is authorized for
  final List<String>? schemas;

  /// Authorization Query Request
  AuthorizationQueryRequest({
    required this.entityId,
    required this.uri,
    this.authorityId,
    this.assertionId,
    this.schemas,
    this.context,
  });
}

/// Represents the different types of DID Accreditations used in a trust chain.
enum DIDAccreditationTypes {
  /// Authorize (Root DID, can authorize a did with accredit, attest permissions)
  authorize('VerifiableAuthorizationForTrustChain'),

  /// Accredit  (Accreditor DID, can authorize other did with attest permissions)
  accredit('VerifiableAccreditationToAccredit'),

  /// Attest    (Attest DID, can issue credentials by proving recognition)
  attest('VerifiableAccreditationToAttest');

  /// type string value
  final String value;

  const DIDAccreditationTypes(this.value);
}

/// A utility class for working with the "did:cheqd" method.
class DidCheqd {
  /// Resolves a [DidDocument] for a given DID.
  ///
  /// [didToResolve] - The DID to resolve.
  ///
  /// Returns a [DidDocument] object.
  static Future<DidDocument> resolve(
    String didToResolve,
  ) async {
    if (!didToResolve.startsWith('did:cheqd')) {
      throw SsiException(
        message: '`$didToResolve` is not did:cheqd DID',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }

    var res = await get(Uri.parse('$cheqdResolverUrl$didToResolve'),
            headers: {'Accept': 'application/json'})
        .timeout(const Duration(seconds: 30), onTimeout: () {
      return Response('Timeout', 408);
    });

    if (res.statusCode == 200) {
      final responseJson = jsonDecode(res.body);
      return DidDocument.fromJson(responseJson['didDocument']);
    } else {
      throw SsiException(
        message: 'Failed to fetch DID Cheqd document for $didToResolve',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  /// Resolves a DidLinkedResource for a given DID.
  ///
  /// [didUrlToResolve] - The DID to resolve.
  ///
  /// Returns a [List<int>] object.
  static Future<List<int>> resolveResource(
    String didUrlToResolve,
  ) async {
    if (!didUrlToResolve.startsWith('did:cheqd')) {
      throw SsiException(
        message: '`$didUrlToResolve` is not did:cheqd DID',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }

    var res = await get(Uri.parse('$cheqdResolverUrl$didUrlToResolve'))
        .timeout(const Duration(seconds: 30), onTimeout: () {
      return Response('Timeout', 408);
    });

    if (res.statusCode == 200) {
      return res.bodyBytes;
    } else {
      throw SsiException(
        message: 'Failed to fetch DID Cheqd document for $didUrlToResolve',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  /// Registers a new did:cheqd using the provided keys.
  ///
  /// This method implements the complete two-step registration process:
  /// 1. Initial registration request
  /// 2. Polling for completion with signature verification
  ///
  /// [publicKeyBase64] - The public key in base64 format.
  /// [privateKeyBase64] - The private key in base64 format.
  /// [network] - The network to register on ('testnet' or 'mainnet'). Defaults to 'testnet'.
  /// [registrarUrl] - Optional custom registrar URL (defaults to localhost:3000).
  ///
  /// Returns the registered DID string.
  ///
  /// Throws [SsiException] if registration fails.
  static Future<String> register(
    String publicKeyBase64,
    String privateKeyBase64, {
    String network = 'testnet',
    String? registrarUrl,
  }) async {
    try {
      // Decode the base64 keys
      final publicKeyBytes = base64Decode(publicKeyBase64);
      final privateKeyBytes = base64Decode(privateKeyBase64);

      // Create a PublicKey object from the bytes
      // Assuming Ed25519 key type for cheqd (most common)
      final publicKey = PublicKey(
        'key-1', // ID for the key
        publicKeyBytes,
        KeyType.ed25519,
      );

      // Generate a unique identifier for the DID
      final didIdentifier = _generateDidIdentifier();
      final did = 'did:cheqd:$network:$didIdentifier';

      // Convert public key to multibase format
      final multiKey = toMultikey(publicKey.bytes, publicKey.type);
      final publicKeyMultibase = toMultiBase(multiKey);

      // Create verification method
      final verificationMethod = publicKey.type == KeyType.p256
          ? VerificationMethodJwk(
              id: '$did#key-1',
              controller: did,
              type: _getVerificationMethodType(publicKey.type),
              publicKeyJwk: _createJwkFromPublicKey(publicKey),
            )
          : VerificationMethodMultibase(
              id: '$did#key-1',
              controller: did,
              type: _getVerificationMethodType(publicKey.type),
              publicKeyMultibase: publicKeyMultibase,
            );

      // Create DID document
      final didDocument = DidDocument.create(
        context: Context.fromJson(_getContextForKeyType(publicKey.type)),
        id: did,
        controller: [did],
        verificationMethod: [verificationMethod],
        authentication: ['$did#key-1'],
        assertionMethod: ['$did#key-1'],
        capabilityInvocation: ['$did#key-1'],
        capabilityDelegation: ['$did#key-1'],
      );

      // Step 1: Initial registration request
      final url = registrarUrl ?? cheqdRegistrarUrl;
      final initialResponse = await _submitInitialRegistration(
        url,
        didDocument,
        network,
      );

      // Step 2: Poll for completion and handle signature verification
      final signingFunction = (Uint8List data) async {
        if (publicKey.type == KeyType.ed25519) {
          final keyPair = Ed25519KeyPair.fromPrivateKey(privateKeyBytes);
          return await keyPair.sign(data);
        } else if (publicKey.type == KeyType.p256) {
          final keyPair = P256KeyPair.fromPrivateKey(privateKeyBytes);
          // Use the standard sign method for P-256
          return await keyPair.sign(data);
        } else {
          throw SsiException(
            message: 'Unsupported key type for signing: ${publicKey.type}',
            code: SsiExceptionType.invalidKeyType.code,
          );
        }
      };
      final registeredDid = await _pollForCompletion(
        url,
        initialResponse,
        signingFunction,
      );

      return registeredDid;
    } catch (e) {
      if (e is SsiException) {
        rethrow;
      }
      throw SsiException(
        message: 'Failed to register DID: $e',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  /// Verifies the trust chain and returns a TRQP-compliant object on success.
  /// Throws a TrustVerificationException on failure.
  static Future<AuthorizationQueryResponse> authorize(
      AuthorizationQueryRequest query) async {
    List<String> accreditorDids = [];
    String uri = query.uri;
    String subject = query.entityId;
    final String? rootAuthority = query.authorityId;
    DIDAccreditationTypes? role = query.assertionId;

    DIDAccreditationTypes? assertionId;

    while (true) {
      final resource = await DidCheqd.resolveResource(uri);
      final accreditation = jsonDecode(utf8.decode(resource));
      final issuerData = accreditation['issuer'];
      final currentIssuer = (issuerData is String)
          ? issuerData // Case 1: 'issuer' is a simple string.
          // Check if the value is a Map (which contains the 'id' we want)
          : (issuerData is Map<String, dynamic>)
              ? issuerData['id'] as String // Case 2: It's a Map, access 'id'.

              // Final Fallback (Catch-all for List, null, or any other unexpected type)
              : throw SsiException(
                  message: 'Invalid issuer in trust chain $issuerData',
                  code: '400');
      final currentSubject = accreditation['credentialSubject']['id'] as String;
      final accreditationType = (accreditation['type'] is List)
          ? (accreditation['type'] as List).cast<String>()
          : throw SsiException(
              message: 'Invalid role type ${accreditation['type']}',
              code: '400');
      // validate subject
      if (subject != currentSubject) {
        return AuthorizationQueryResponse(
            entityId: query.entityId,
            message:
                'Expected subject DID $subject in trust chain, but found $currentSubject',
            authorized: false);
      }

      // Validate role in the ecosystem
      assertionId = accreditationType
              .contains(DIDAccreditationTypes.authorize.value)
          ? DIDAccreditationTypes.authorize
          : accreditationType.contains(DIDAccreditationTypes.accredit.value)
              ? DIDAccreditationTypes.accredit
              : accreditationType.contains(DIDAccreditationTypes.attest.value)
                  ? DIDAccreditationTypes.attest
                  : null;

      if (role != null && accreditorDids.isEmpty && role != assertionId) {
        return AuthorizationQueryResponse(
            entityId: query.entityId,
            message:
                'Expected entity role $role in trust chain, but found $assertionId',
            authorized: false);
      }

      // validate schema permissions
      if (query.schemas != null) {
        final List<dynamic> accreditationForData =
            (accreditation['credentialSubject']?['accreditedFor']
                    as List<dynamic>?) ??
                [];

        final bool hasAllRequiredSchemas = accreditationForData.every((schema) {
          final schemaTypes = (schema['types'] as List<dynamic>?) ?? [];
          final schemaId = schema['schemaId'];

          return accreditationForData.any((accredited) {
            final accreditedTypes =
                (accredited['types'] as List<dynamic>?) ?? [];
            final accreditedSchemaId = accredited['schemaId'];

            final hasAllTypes = schemaTypes.every(accreditedTypes.contains);
            return hasAllTypes && accreditedSchemaId == schemaId;
          });
        });

        if (!hasAllRequiredSchemas) {
          return AuthorizationQueryResponse(
              entityId: query.entityId,
              message: 'Authorized entity $subject does not have permissions',
              authorized: false);
        }
      }

      // End the loop after finding the rootDid
      if (accreditationType.contains(DIDAccreditationTypes.authorize.value)) {
        // SUCCESS: Accreditation is a root/terminal type, and all trust links passed.
        return AuthorizationQueryResponse(
            entityId: query.entityId,
            authorized:
                rootAuthority != null ? rootAuthority == currentSubject : true,
            message: 'Accreditation trust chain successfully verified.',
            accreditorDids: accreditorDids,
            authorityId: currentSubject,
            assertionId: assertionId);
      } else {
        final termsOfUse = accreditation['termsOfUse'];
        if (termsOfUse == null ||
            termsOfUse['parentAccreditation'] == null ||
            (termsOfUse['rootAuthorization'] == null &&
                termsOfUse['rootAuthorization'] is String)) {
          return AuthorizationQueryResponse(
              entityId: query.entityId,
              message:
                  'Missing parentAccreditaiton/rootAuthorization required for delegated trust link',
              authorized: false);
        }

        // Validate root if provided in every authority
        // final currentRootAuthority = termsOfUse['rootAuthorization'] as String;
        // print(currentRootAuthority);

        // Prepare for next iteration (traversing up the chain)
        accreditorDids.add(currentIssuer);
        uri = termsOfUse['parentAccreditation'] as String;
        subject = currentIssuer;
      }
    }
  }

  /// Determines the verification method type based on the key type.
  /// Only supports ed25519 and P-256 keys.
  static String _getVerificationMethodType(KeyType keyType) {
    switch (keyType) {
      case KeyType.ed25519:
        return 'Ed25519VerificationKey2020';
      case KeyType.p256:
        return 'JsonWebKey2020';
      default:
        throw SsiException(
          message:
              'Unsupported key type: $keyType. Only ed25519 and P-256 are supported.',
          code: SsiExceptionType.invalidKeyType.code,
        );
    }
  }

  /// Determines the context array based on the key type.
  static List<String> _getContextForKeyType(KeyType keyType) {
    switch (keyType) {
      case KeyType.ed25519:
        return [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1',
        ];
      case KeyType.p256:
        return [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1',
        ];
      default:
        throw SsiException(
          message:
              'Unsupported key type: $keyType. Only ed25519 and P-256 are supported.',
          code: SsiExceptionType.invalidKeyType.code,
        );
    }
  }

  /// Creates a JWK from a public key for supported key types.
  static Jwk _createJwkFromPublicKey(PublicKey publicKey) {
    if (publicKey.type != KeyType.p256 && publicKey.type != KeyType.ed25519) {
      throw SsiException(
        message: 'JWK creation is only supported for P-256 and Ed25519 keys',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }

    // Use the existing utility function to convert public key to JWK
    final jwkMap = keyToJwk(publicKey);
    return Jwk.fromJson(jwkMap);
  }

  /// Registers a new did:cheqd using a wallet and key IDs.
  ///
  /// This method implements the complete two-step registration process:
  /// 1. Initial registration request
  /// 2. Polling for completion with signature verification
  ///
  /// [wallet] - The wallet instance containing the keys.
  /// [keyIds] - The identifiers of the keys in the wallet. At least one must be Ed25519.
  /// [network] - The network to register on ('testnet' or 'mainnet'). Defaults to 'testnet'.
  /// [registrarUrl] - Optional custom registrar URL (defaults to localhost:3000).
  ///
  /// Returns the registered DID string.
  ///
  /// Throws [SsiException] if registration fails.
  static Future<String> registerWithWallet(
    Wallet wallet,
    List<String> keyIds, {
    String network = 'testnet',
    String? registrarUrl,
  }) async {
    try {
      // Validate that we have at least one key
      if (keyIds.isEmpty) {
        throw SsiException(
          message: 'At least one key ID must be provided.',
          code: SsiExceptionType.invalidKeyType.code,
        );
      }

      // Get all public keys from the wallet
      final publicKeys = <String, PublicKey>{};
      for (final keyId in keyIds) {
        final publicKey = await wallet.getPublicKey(keyId);
        publicKeys[keyId] = publicKey;
      }

      // Find the Ed25519 key for signing (required)
      String? ed25519KeyId;
      final p256KeyIds = <String>[];

      for (final entry in publicKeys.entries) {
        final keyId = entry.key;
        final publicKey = entry.value;

        if (publicKey.type == KeyType.ed25519) {
          ed25519KeyId = keyId;
        } else if (publicKey.type == KeyType.p256) {
          p256KeyIds.add(keyId);
        } else {
          throw SsiException(
            message:
                'Unsupported key type: ${publicKey.type}. Only ed25519 and P-256 are supported.',
            code: SsiExceptionType.invalidKeyType.code,
          );
        }
      }

      // Validate that we have at least one Ed25519 key
      if (ed25519KeyId == null) {
        throw SsiException(
          message: 'At least one Ed25519 key is required for signing.',
          code: SsiExceptionType.invalidKeyType.code,
        );
      }

      // For the private key, we need to create a signing function that uses the wallet
      // This is more secure as the private key never leaves the wallet
      Future<Uint8List> signingFunction(Uint8List data) async {
        return await wallet.sign(data, keyId: ed25519KeyId!);
      }

      // Generate a unique identifier for the DID
      final didIdentifier = _generateDidIdentifier();
      final did = 'did:cheqd:$network:$didIdentifier';

      // Create verification methods
      final verificationMethods = <VerificationMethod>[];
      final authenticationMethods = <String>[];
      final assertionMethods = <String>[];
      final capabilityInvocationMethods = <String>[];
      final capabilityDelegationMethods = <String>[];
      final keyAgreementMethods = <String>[];

      // Add Ed25519 key as primary verification method in JWK format
      final ed25519PublicKey = publicKeys[ed25519KeyId]!;

      final ed25519VerificationMethod = VerificationMethodJwk(
        id: '$did#key-1',
        controller: did,
        type: 'JsonWebKey2020',
        publicKeyJwk: _createJwkFromPublicKey(ed25519PublicKey),
      );

      verificationMethods.add(ed25519VerificationMethod);
      authenticationMethods.add('$did#key-1');
      assertionMethods.add('$did#key-1');
      capabilityInvocationMethods.add('$did#key-1');
      capabilityDelegationMethods.add('$did#key-1');

      // Add P-256 keys as JWK format for key agreement
      int keyIndex = 2;
      for (final p256KeyId in p256KeyIds) {
        final p256PublicKey = publicKeys[p256KeyId]!;
        final p256VerificationMethod = VerificationMethodJwk(
          id: '$did#key-$keyIndex',
          controller: did,
          type: _getVerificationMethodType(p256PublicKey.type),
          publicKeyJwk: _createJwkFromPublicKey(p256PublicKey),
        );

        verificationMethods.add(p256VerificationMethod);
        keyAgreementMethods.add('$did#key-$keyIndex');
        keyIndex++;
      }

      // Create DID document
      final didDocument = DidDocument.create(
        context: Context.fromJson(_getContextForKeyType(ed25519PublicKey.type)),
        id: did,
        controller: [did],
        verificationMethod:
            verificationMethods.cast<EmbeddedVerificationMethod>(),
        authentication: authenticationMethods,
        assertionMethod: assertionMethods,
        capabilityInvocation: capabilityInvocationMethods,
        capabilityDelegation: capabilityDelegationMethods,
        keyAgreement:
            keyAgreementMethods.isNotEmpty ? keyAgreementMethods : null,
      );

      // Step 1: Initial registration request
      final url = registrarUrl ?? cheqdRegistrarUrl;
      final initialResponse = await _submitInitialRegistration(
        url,
        didDocument,
        network,
        signingFunction: signingFunction,
      );

      // Step 2: Poll for completion and handle signature verification
      final registeredDid = await _pollForCompletion(
        url,
        initialResponse,
        signingFunction,
      );

      return registeredDid;
    } catch (e) {
      if (e is SsiException) {
        rethrow;
      }
      throw SsiException(
        message: 'Failed to register DID: $e',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  /// Submits the initial registration request to the cheqd registrar.
  static Future<Map<String, dynamic>> _submitInitialRegistration(
    String registrarUrl,
    DidDocument didDocument,
    String network, {
    Future<Uint8List> Function(Uint8List)? signingFunction,
  }) async {
    // Prepare the request payload
    final requestPayload = {
      'didDocument': didDocument.toJson(),
      'options': {
        'network': network,
      },
    };

    final response = await post(
      Uri.parse('$registrarUrl/1.0/create'),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: jsonEncode(requestPayload),
    ).timeout(const Duration(seconds: 60));

    if (response.statusCode == 202) {
      // 202 Accepted - registration initiated, need to poll for completion
      final responseData = jsonDecode(response.body);
      responseData['_originalPayload'] = requestPayload;
      if (signingFunction != null) {
        responseData['_signingFunction'] = signingFunction;
      }
      return responseData;
    } else if (response.statusCode == 201 || response.statusCode == 200) {
      // Immediate success (some registrars may return this)
      final responseJson = jsonDecode(response.body);
      responseJson['_originalPayload'] = requestPayload;
      if (signingFunction != null) {
        responseJson['_signingFunction'] = signingFunction;
      }
      return responseJson;
    } else {
      throw SsiException(
        message:
            'Failed to submit initial registration: ${response.statusCode} - ${response.body}',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  /// Polls the registrar for completion and handles signature verification.
  static Future<String> _pollForCompletion(
    String registrarUrl,
    Map<String, dynamic> initialResponse,
    Future<Uint8List> Function(Uint8List) signingFunction,
  ) async {
    final jobId = initialResponse['jobId'] ?? initialResponse['id'];
    if (jobId == null) {
      // If no job ID, assume immediate completion
      return initialResponse['did'] ?? initialResponse['didState']?['did'];
    }

    // Check if the initial response already requires action
    final didState = initialResponse['didState'];
    if (didState != null) {
      final state = didState['state'];
      if (state == 'action') {
        // Handle signature requirement from initial response
        final originalPayload =
            initialResponse['_originalPayload'] as Map<String, dynamic>;
        final result = await _handleSignatureRequirement(
          registrarUrl,
          jobId,
          didState,
          signingFunction,
          originalPayload['didDocument'],
          originalPayload['options'],
        );
        if (result != null) {
          return result;
        }
      } else if (state == 'finished' || state == 'completed') {
        final did = didState['did'];
        if (did != null) {
          return did;
        }
      }
    }

    const maxAttempts = 30; // Maximum polling attempts
    const pollInterval = Duration(seconds: 2);

    for (int attempt = 0; attempt < maxAttempts; attempt++) {
      await Future<void>.delayed(pollInterval);

      try {
        final statusResponse = await get(
          Uri.parse('$registrarUrl/1.0/create/$jobId'),
          headers: {'Accept': 'application/json'},
        ).timeout(const Duration(seconds: 30));

        if (statusResponse.statusCode == 200) {
          final statusBody = jsonDecode(statusResponse.body);
          final didState = statusBody['didState'] ?? statusBody;
          final state = didState['state'] ?? statusBody['state'];

          if (state == 'finished' || state == 'completed') {
            // Registration completed successfully
            final did = didState['did'];

            if (did != null) {
              return did;
            }
          } else if (state == 'failed' || state == 'error') {
            final error =
                statusBody['error'] ?? statusBody['message'] ?? 'Unknown error';
            throw SsiException(
              message: 'DID registration failed: $error',
              code: SsiExceptionType.invalidDidCheqd.code,
            );
          } else if (state == 'action') {
            // Check if we need to sign something
            final action = didState['action'] ?? statusBody['action'];
            if (action != null &&
                action.toString().toLowerCase().contains('sign')) {
              // Handle signature requirement
              final originalPayload =
                  initialResponse['_originalPayload'] as Map<String, dynamic>;
              final result = await _handleSignatureRequirement(
                registrarUrl,
                jobId,
                didState,
                signingFunction,
                originalPayload['didDocument'],
                originalPayload['options'],
              );
              if (result != null) {
                return result;
              }
            }
            // Continue polling
          }
        } else {
          throw SsiException(
            message:
                'Failed to fetch registration status: ${statusResponse.statusCode}',
            code: SsiExceptionType.invalidDidCheqd.code,
          );
        }
      } catch (e) {
        if (attempt == maxAttempts - 1) {
          rethrow;
        }
        // Continue polling on error (might be temporary network issue)
      }
    }

    throw SsiException(
      message:
          'DID registration polling timed out after ${maxAttempts * pollInterval.inSeconds} seconds',
      code: SsiExceptionType.invalidDidCheqd.code,
    );
  }

  /// Handles signature requirements during the registration process.
  static Future<String?> _handleSignatureRequirement(
    String registrarUrl,
    String jobId,
    Map<String, dynamic> statusBody,
    Future<Uint8List> Function(Uint8List) signingFunction,
    Map<String, dynamic> originalDidDocument,
    Map<String, dynamic> originalOptions,
  ) async {
    try {
      // Extract the signing request from the response
      final signingRequest =
          statusBody['signingRequest'] as Map<String, dynamic>?;
      if (signingRequest == null) {
        throw SsiException(
          message: 'No signing request provided',
          code: SsiExceptionType.invalidDidCheqd.code,
        );
      }

      // Process each signing request
      final signingResponse = <String, Map<String, dynamic>>{};

      for (final entry in signingRequest.entries) {
        final requestId = entry.key;
        final request = entry.value as Map<String, dynamic>;

        final kid = request['kid'] as String;
        final serializedPayload = request['serializedPayload'] as String;

        // Decode the base64 payload
        final payloadBytes = base64Decode(serializedPayload);

        // Sign the payload using the provided signing function
        final signature = await signingFunction(payloadBytes);

        // Add to signing response with the correct structure
        signingResponse[requestId] = {
          'kid': kid,
          'signature': base64Encode(signature),
        };
      }

      // Create the secret object
      final secret = {
        'signingResponse': signingResponse,
      };

      // Resubmit the complete request with the signature
      final completePayload = {
        'jobId': jobId,
        'secret': secret,
        'options': originalOptions,
        'didDocument': originalDidDocument,
      };

      final signatureResponse = await post(
        Uri.parse('$registrarUrl/1.0/create/'),
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: jsonEncode(completePayload),
      ).timeout(const Duration(seconds: 30));

      if (signatureResponse.statusCode == 200 ||
          signatureResponse.statusCode == 201 ||
          signatureResponse.statusCode == 202) {
        // Check if the response indicates completion
        final responseData = jsonDecode(signatureResponse.body);
        final didState = responseData['didState'];
        if (didState != null && didState['state'] == 'finished') {
          final did = didState['did'];
          if (did != null) {
            // Return the DID directly from the signature response
            return did;
          }
        }
      } else {
        throw SsiException(
          message:
              'Failed to submit signature: ${signatureResponse.statusCode} - ${signatureResponse.body}',
          code: SsiExceptionType.invalidDidCheqd.code,
        );
      }

      // If we get here, the signature was submitted but registration is still pending
      return null;
    } catch (e) {
      if (e is SsiException) {
        rethrow;
      }
      throw SsiException(
        message: 'Failed to handle signature requirement: $e',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  /// Generates a unique DID identifier using UUID v4 format.
  ///
  /// Returns a UUID v4 string that can be used as a DID identifier.
  static String _generateDidIdentifier() {
    final random = Random.secure();
    final uuidBytes = Uint8List(16);
    for (int i = 0; i < 16; i++) {
      uuidBytes[i] = random.nextInt(256);
    }

    // Set version (4) and variant bits for UUID v4
    uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40; // Version 4
    uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80; // Variant bits

    // Convert to proper UUID string format (hex)
    return [
      uuidBytes
          .sublist(0, 4)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(''),
      uuidBytes
          .sublist(4, 6)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(''),
      uuidBytes
          .sublist(6, 8)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(''),
      uuidBytes
          .sublist(8, 10)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(''),
      uuidBytes
          .sublist(10, 16)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(''),
    ].join('-');
  }
}
