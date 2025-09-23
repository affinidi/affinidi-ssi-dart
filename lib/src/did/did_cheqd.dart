import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../json_ld/context.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../util/base64_util.dart';
import 'did_document/index.dart';
import 'public_key_utils.dart';

/// The URL for the Cheqd DID resolver service.
String cheqdResolverUrl = 'https://resolver.cheqd.net/1.0/identifiers/';

/// The base URL for the Cheqd DID registrar service (running locally).
String cheqdRegistrarUrl = 'http://localhost:3000';

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
      // Using a simple approach with timestamp and random bytes
      // Generate a UUID v4 for the DID identifier
      final random = Random.secure();
      final uuidBytes = Uint8List(16);
      for (int i = 0; i < 16; i++) {
        uuidBytes[i] = random.nextInt(256);
      }

      // Set version (4) and variant bits for UUID v4
      uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40; // Version 4
      uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80; // Variant bits

      // Convert to proper UUID string format (hex)
      final didIdentifier = [
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

      // Create the DID
      final did = 'did:cheqd:$network:$didIdentifier';

      // Convert public key to multibase format
      final multiKey = toMultikey(publicKey.bytes, publicKey.type);
      final publicKeyMultibase = toMultiBase(multiKey);

      // Create verification method
      final verificationMethod = VerificationMethodMultibase(
        id: '$did#key-1',
        controller: did,
        type: 'Ed25519VerificationKey2020',
        publicKeyMultibase: publicKeyMultibase,
      );

      // Create DID document
      final didDocument = DidDocument.create(
        context: Context.fromJson([
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1',
        ]),
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
        publicKeyBytes,
        privateKeyBytes,
        network,
      );

      // Step 2: Poll for completion and handle signature verification
      final registeredDid = await _pollForCompletion(
        url,
        initialResponse,
        privateKeyBytes,
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
    Uint8List publicKeyBytes,
    Uint8List privateKeyBytes,
    String network,
  ) async {
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
      return responseData;
    } else if (response.statusCode == 201 || response.statusCode == 200) {
      // Immediate success (some registrars may return this)
      final responseJson = jsonDecode(response.body);
      responseJson['_originalPayload'] = requestPayload;
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
    Uint8List privateKeyBytes,
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
          privateKeyBytes,
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
                privateKeyBytes,
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
    Uint8List privateKeyBytes,
    Map<String, dynamic> originalDidDocument,
    Map<String, dynamic> originalOptions,
  ) async {
    try {
      // Extract the signing request from the response
      final signingRequest = statusBody['signingRequest'];
      if (signingRequest == null) {
        throw SsiException(
          message: 'No signing request provided',
          code: SsiExceptionType.invalidDidCheqd.code,
        );
      }

      // Create Ed25519 key pair for signing
      final keyPair = Ed25519KeyPair.fromPrivateKey(privateKeyBytes);

      // Process each signing request
      final signingResponse = <String, Map<String, dynamic>>{};

      for (final entry in signingRequest.entries) {
        final requestId = entry.key;
        final request = entry.value as Map<String, dynamic>;

        final kid = request['kid'] as String;
        final alg = request['alg'] as String;
        final serializedPayload = request['serializedPayload'] as String;

        // Decode the base64 payload
        final payloadBytes = base64Decode(serializedPayload);

        // Sign the payload
        final signature = await keyPair.sign(payloadBytes);

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
}
