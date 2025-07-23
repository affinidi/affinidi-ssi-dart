import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../../../ssi.dart';
import '../models/field_types/credential_status/revocation_list_2020.dart';

/// Verifier that checks if a Verifiable Credential is revoked using RevocationList2020Status.
class RevocationList2020Verifier implements VcVerifier {
  /// A function that fetches the status list credential from the given [Uri].
  ///
  /// The status list credential must contain a `credentialSubject.encodedList`
  /// field encoded as base64-url.
  final Future<Map<String, dynamic>> Function(Uri uri)?
      fetchStatusListCredential;

  /// Custom document loader for loading external resources.
  final DocumentLoader? customDocumentLoader;

  /// Creates a new [RevocationList2020Verifier] with optional fetch function and document loader.
  ///
  /// If [fetchStatusListCredential] is not provided, the verifier will use
  /// [customDocumentLoader] or the default document loader to fetch status lists.
  RevocationList2020Verifier({
    this.fetchStatusListCredential,
    this.customDocumentLoader,
  });

  /// Fetches the status list credential using the configured loader.
  Future<Map<String, dynamic>> _fetchStatusList(Uri uri) async {
    if (fetchStatusListCredential != null) {
      return await fetchStatusListCredential!(uri);
    }

    if (customDocumentLoader == null) {
      throw Exception('No document loader available to fetch status list');
    }

    final document = await customDocumentLoader!(uri);

    if (document == null) {
      throw Exception('Could not load RevocationList2020Credential from $uri');
    }

    return document;
  }

  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential vc) async {
    final statuses = getCredentialStatusFromVc(vc);

    if (statuses.isEmpty) {
      return VerificationResult.ok();
    }

    final errors = <String>[];

    for (final status in statuses) {
      final listUri = Uri.tryParse(status.revocationListCredential);
      final index = int.tryParse(status.revocationListIndex);

      if (listUri == null || index == null) {
        errors
            .add('${SsiExceptionType.invalidVC.code} for status ${status.id}');
        continue;
      }

      Map<String, dynamic> statusListVc;
      try {
        statusListVc = await _fetchStatusList(listUri);
      } catch (e) {
        errors.add(
            '${SsiExceptionType.failedToFetchRevocationList.code} for status ${status.id}: $e');
        continue;
      }

      final encodedList = statusListVc['credentialSubject']?['encodedList'];
      if (encodedList == null || encodedList is! String) {
        errors
            .add('${SsiExceptionType.invalidVC.code} for status ${status.id}');
        continue;
      }

      Uint8List bitstring;
      try {
        final compressed = base64Url.decode(encodedList);
        bitstring = Uint8List.fromList(gzip.decode(compressed));
      } catch (_) {
        errors.add(
            '${SsiExceptionType.invalidEncoding.code} for status ${status.id}');
        continue;
      }

      final byteIndex = index ~/ 8;
      final bitOffset = index % 8;

      if (byteIndex >= bitstring.length) {
        errors.add(
            '${SsiExceptionType.revocationIndexOutOfBounds.code} for status ${status.id}');
        continue;
      }

      final byte = bitstring[byteIndex];
      final isRevoked = (byte & (1 << bitOffset)) != 0;

      if (isRevoked) {
        errors
            .add('${SsiExceptionType.invalidVC.code} for status ${status.id}');
      }
    }

    return errors.isEmpty
        ? VerificationResult.ok()
        : VerificationResult.invalid(errors: errors);
  }
}

/// Extracts and parses all [RevocationList2020Status] entries from a VC.
///
/// This function normalizes the `credentialStatus` field from all supported
/// credential models and returns a list of [RevocationList2020Status] entries
/// found in the VC.
///
/// Returns an empty list if no valid entries are found.
List getCredentialStatusFromVc(ParsedVerifiableCredential vc) {
  List<Map<String, dynamic>> credentialStatus;

  switch (vc) {
    case LdVcDataModelV1():
      final status = vc.credentialStatus;
      credentialStatus = status == null ? [] : [status.toJson()];
      break;
    case LdVcDataModelV2():
      credentialStatus =
          vc.credentialStatus.map((status) => status.toJson()).toList();
      break;
    case JwtVcDataModelV1():
      final status = vc.credentialStatus;
      credentialStatus = status == null ? [] : [status.toJson()];
      break;
    case SdJwtDataModelV2():
      credentialStatus =
          vc.credentialStatus.map((status) => status.toJson()).toList();
      break;
    default:
      return [];
  }

  final statuses = <RevocationList2020Status>[];
  for (final status in credentialStatus) {
    final type = status['type'];
    if (type == 'RevocationList2020Status') {
      final revocationStatus = RevocationList2020Status.fromJson(status);
      statuses.add(revocationStatus);
    }
  }
  return statuses;
}
