import 'dart:convert';
import 'dart:typed_data';

import '../../../ssi.dart';

class RevocationList2020Verifier implements VcVerifier {
  final Future<Map<String, dynamic>> Function(Uri uri)
      fetchStatusListCredential;

  RevocationList2020Verifier({required this.fetchStatusListCredential});

  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential vc) async {
    final status = getCredentialStatusFromVc(vc);

    if (status == null) {
      return VerificationResult.invalid(
        errors: ['Missing or unsupported credentialStatus'],
      );
    }

    final listUri = Uri.tryParse(status.revocationListCredential);
    final index = int.tryParse(status.revocationListIndex);

    if (listUri == null || index == null) {
      return VerificationResult.invalid(
        errors: ['Invalid revocationListCredential or revocationListIndex'],
      );
    }

    Map<String, dynamic> statusListVc;
    try {
      statusListVc = await fetchStatusListCredential(listUri);
    } catch (e) {
      return VerificationResult.invalid(
        errors: ['Failed to fetch revocation list: $e'],
      );
    }

    final encodedList = statusListVc['credentialSubject']?['encodedList'];

    if (encodedList == null || encodedList is! String) {
      return VerificationResult.invalid(
        errors: ['Missing or invalid encodedList in status VC'],
      );
    }

    Uint8List bitstring;
    try {
      bitstring = base64Url.decode(encodedList);
    } catch (_) {
      return VerificationResult.invalid(
        errors: ['Missing or invalid encodedList in status VC'],
      );
    }

    final byteIndex = index ~/ 8;
    final bitOffset = index % 8;

    if (byteIndex >= bitstring.length) {
      return VerificationResult.invalid(
        errors: ['Revocation index $index out of bounds'],
      );
    }

    final byte = bitstring[byteIndex];
    final isRevoked = (byte & (1 << (7 - bitOffset))) != 0;

    return isRevoked
        ? VerificationResult.invalid(errors: ['Credential is revoked'])
        : VerificationResult.ok();
  }

  @override
  Future<List<VerificationResult>> verifyList(
      List<ParsedVerifiableCredential> vcs) {
    return Future.wait(vcs.map(verify));
  }
}
