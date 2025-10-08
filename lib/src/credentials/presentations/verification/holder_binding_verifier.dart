import '../../../../ssi.dart';

/// Verifies that all VCs inside a Verifiable Presentation (VP)
/// are bound to the VP holder.
///
/// Rules:
/// - Prefer `vc.holder.id` as the credential holder.
/// - If `vc.holder` does not exist, fallback to all `credentialSubject.[i].id`.
/// - The credential holder (or one of the subject IDs) must match the VP holder.
/// - If no holder or subject IDs exist, mark as invalid.
class HolderBindingVerifier implements VpVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation vp) async {
    final vpHolderDid = vp.holder.id.toString();
    final errors = <String>[];

    for (final vc in vp.verifiableCredential) {
      if (vc is! LdVcDataModelV1) {
        continue;
      }
      final vcId = vc.id?.toString() ?? '<unknown-vc>';
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
