import '../../../../ssi.dart';

/// Type identifier used to recognize Delegation VCs
const String delegationVcType = 'DelegationCredential';

/// A verifier for checking the validity of delegations in a Verifiable Presentation (VP).
///
/// It ensures that:
/// - If a VC in the presentation is held by someone other than the VP holder,
///   a corresponding Delegation VC exists for that holder.
/// - The delegation level in the Delegation VC is either `full` or `restricted`.
class DelegationVcVerifier implements VpVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation vp) async {
    final credentials = vp.verifiableCredential;
    final vpHolderDid = vp.holder.id.toString();

    final delegationCredentialsMap = <String, ParsedVerifiableCredential>{};
    final externalHolderVcIdsMap = <String, List<String>>{};
    bool isValidDelegationCheck = true;
    final delegationErrors = <String>[];

    for (final credential in credentials) {
      final isDelegation = credential.type.contains(delegationVcType);
      final issuerDid = credential.issuer.id;

      if (isDelegation) {
        delegationCredentialsMap[issuerDid.toString()] = credential;
      }

      final holderJson = credential.toJson()['holder'];
      final holderDid = holderJson is String
          ? holderJson
          : (holderJson as Map<String, dynamic>?)?['id'] as String?;

      final vcHolderDids = holderDid != null
          ? [holderDid]
          : credential.credentialSubject
              .map((subject) => subject.id?.toString())
              .where((id) => id != null)
              .cast<String>()
              .toList();

      if (vcHolderDids.isEmpty) {
        continue;
      }

      for (final vcHolderDid in vcHolderDids) {
        if (vcHolderDid != vpHolderDid) {
          if (isDelegation) {
            isValidDelegationCheck = false;
            delegationErrors.add(
                'Delegation VC ${credential.id} cannot be delegated for: $vpHolderDid');
            continue;
          }
          externalHolderVcIdsMap
              .putIfAbsent(vcHolderDid, () => [])
              .add(credential.id.toString());
        }
      }
    }

    for (final externalHolderDid in externalHolderVcIdsMap.keys) {
      final vcIds = externalHolderVcIdsMap[externalHolderDid]!;
      final delegationCredentialBySigner =
          delegationCredentialsMap[externalHolderDid];

      if (delegationCredentialBySigner == null) {
        isValidDelegationCheck = false;
        delegationErrors.add('Missing Delegation VC from: $externalHolderDid');
        continue;
      }

      final subject = delegationCredentialBySigner.credentialSubject;
      final delegationLevel = subject.first['delegationLevel'] ?? 'restricted';

      if (delegationLevel == 'full') {
        continue;
      }

      if (delegationLevel != 'restricted' && delegationLevel != 'full') {
        isValidDelegationCheck = false;
        delegationErrors
            .add('Invalid delegation level: $delegationLevel for VC '
                '${delegationCredentialBySigner.id}');
        continue;
      }

      final rawCredentials =
          subject.first['credentials'] as List<dynamic>? ?? [];

      final delegationCredentialIds = rawCredentials
          .whereType<Map>()
          .map((cred) => cred['id']?.toString())
          .whereType<String>()
          .toList();

      final missedVcs = vcIds
          .where((vcId) => !delegationCredentialIds
              .map((e) => e.toLowerCase())
              .contains(vcId.toLowerCase()))
          .toList();

      if (missedVcs.isNotEmpty) {
        isValidDelegationCheck = false;
        delegationErrors
            .add('Missing delegation VC IDs: ${missedVcs.join(', ')}');
      }

      final unexpectedVcs = delegationCredentialIds
          .where((vcId) =>
              !vcIds.map((e) => e.toLowerCase()).contains(vcId.toLowerCase()))
          .toList();
      if (unexpectedVcs.isNotEmpty) {
        isValidDelegationCheck = false;
        delegationErrors.add(
            'Unexpected VCs in the Delegation VC: ${unexpectedVcs.join(', ')}');
      }

      final delegationHolderJson =
          delegationCredentialBySigner.toJson()['holder'];
      final delegationHolderId = delegationHolderJson is String
          ? delegationHolderJson
          : (delegationHolderJson as Map<String, dynamic>?)?['id'] as String?;

      if (delegationHolderId != vpHolderDid) {
        isValidDelegationCheck = false;
        delegationErrors
            .add('Invalid delegation VC holder: $delegationHolderId');
      }
    }

    return isValidDelegationCheck
        ? VerificationResult.ok()
        : VerificationResult.invalid(errors: delegationErrors);
  }
}
