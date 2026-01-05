import '../../../../ssi.dart';

/// Verifies that all VCs inside a Verifiable Presentation (VP)
/// are bound to the VP holder.
///
/// This verifier checks basic holder binding. Delegation scenarios are handled
/// by [DelegationVcVerifier] which runs before this verifier.
///
/// Rules:
/// - Prefer `vc.holder.id` as the credential holder.
/// - If `vc.holder` does not exist, fallback to all `credentialSubject.[i].id`.
/// - The credential holder (or one of the subject IDs) should match the VP holder.
/// - If no holder or subject IDs exist, mark as invalid.
/// - DelegationCredentials are skipped (handled by DelegationVcVerifier).
class HolderBindingVerifier implements VpVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation vp) async {
    final vpHolderDid = vp.holder.id.toString();
    final errors = <String>[];

    // Pass 1: Collect all delegated credential IDs from DelegationCredentials
    final delegatedCredentialIds = <String>{};
    for (final vc in vp.verifiableCredential) {
      if (vc is LdVcDataModelV1 && vc.type.contains('DelegationCredential')) {
        // Extract credential IDs from the delegation's credentialSubject.credentials array
        final subjects = vc.credentialSubject;
        for (final subject in subjects) {
          final credentials = subject.additionalProperties['credentials'];
          if (credentials is List) {
            for (final cred in credentials) {
              if (cred is Map && cred['id'] is String) {
                delegatedCredentialIds.add(cred['id'] as String);
              }
            }
          }
        }
      }
    }

    // Pass 2: Check holder binding for non-delegation credentials
    for (final vc in vp.verifiableCredential) {
      if (vc is! LdVcDataModelV1) {
        continue;
      }

      // Skip DelegationCredentials - they are handled by DelegationVcVerifier
      if (vc.type.contains('DelegationCredential')) {
        continue;
      }

      final vcId = vc.id?.toString() ?? '<unknown-vc>';
      
      // Skip credentials that are listed as delegated in a DelegationCredential
      if (delegatedCredentialIds.contains(vcId)) {
        continue;
      }

      final holderId = vc.holder?.id.toString();

      if (holderId != null && holderId.isNotEmpty) {
        if (holderId != vpHolderDid) {
          errors.add(
            'VC $vcId holder $holderId does not match VP holder $vpHolderDid',
          );
        }
      } else {
        final subjects = vc.credentialSubject;
        if (subjects.isEmpty) {
          errors.add(
            'VC $vcId has no holder and no credentialSubject IDs',
          );
          continue;
        }

        final subjectIds = subjects
            .map((s) => s.id?.toString())
            .where((id) => id != null && id.isNotEmpty)
            .cast<String>()
            .toList();

        if (subjectIds.isEmpty) {
          errors.add(
            'VC $vcId has no valid credentialSubject IDs',
          );
        } else if (!subjectIds.contains(vpHolderDid)) {
          errors.add(
            'VC $vcId subject IDs $subjectIds do not include VP holder $vpHolderDid',
          );
        }
      }
    }

    return errors.isEmpty
        ? VerificationResult.ok()
        : VerificationResult.invalid(errors: errors);
  }
}
