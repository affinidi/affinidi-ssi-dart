import 'dart:convert';
import 'dart:typed_data';

import '../../../ssi.dart';
import '../models/revocation_list_2020.dart';

/// Verifier that checks if a Verifiable Credential is revoked using RevocationList2020Status./// Verifier that checks if a Verifiable Credential is revoked using RevocationList2020Status.
class RevocationList2020Verifier implements VcVerifier {
  /// A function that fetches the status list credential from the given [Uri].
  ///
  /// The status list credential must contain a `credentialSubject.encodedList`
  /// field encoded as base64-url.
  final Future<Map<String, dynamic>> Function(Uri uri)
      fetchStatusListCredential;

  /// Creates a new [RevocationList2020Verifier] with a fetch function.
  ///
  /// The [fetchStatusListCredential] function should retrieve and return
  /// the full status list VC document from a remote URI.
  RevocationList2020Verifier({required this.fetchStatusListCredential});

  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential vc) async {
    final statuses = getCredentialStatusFromVc(vc);

    if (statuses.isEmpty) {
      return VerificationResult.invalid(
        errors: ['Missing or unsupported credentialStatus'],
      );
    }

    final errors = <String>[];

    for (final status in statuses) {
      final listUri = Uri.tryParse(status.revocationListCredential);
      final index = int.tryParse(status.revocationListIndex);

      if (listUri == null || index == null) {
        errors.add(
            'Invalid revocationListCredential or revocationListIndex for status ${status.id}');
        continue;
      }

      Map<String, dynamic> statusListVc;
      try {
        statusListVc = await fetchStatusListCredential(listUri);
      } catch (e) {
        errors
            .add('Failed to fetch revocation list for status ${status.id}: $e');
        continue;
      }

      final encodedList = statusListVc['credentialSubject']?['encodedList'];
      if (encodedList == null || encodedList is! String) {
        errors.add(
            'Missing or invalid encodedList in status VC for status ${status.id}');
        continue;
      }

      Uint8List bitstring;
      try {
        bitstring = base64Url.decode(encodedList);
      } catch (_) {
        errors.add('Invalid encodedList in status VC for status ${status.id}');
        continue;
      }

      final byteIndex = index ~/ 8;
      final bitOffset = index % 8;

      if (byteIndex >= bitstring.length) {
        errors.add(
            'Revocation index $index out of bounds for status ${status.id}');
        continue;
      }

      final byte = bitstring[byteIndex];
      final isRevoked = (byte & (1 << (7 - bitOffset))) != 0;

      if (isRevoked) {
        errors.add('Credential is revoked for status ${status.id}');
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
