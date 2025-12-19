import '../../../../ssi.dart';

/// Type identifier for Delegation VCs
const String _delegationVcType = 'DelegationCredential';

/// Verifies that all VCs inside a Verifiable Presentation (VP)
/// are bound to the VP holder, with support for delegation.
///
/// Rules:
/// - Prefer `vc.holder.id` as the credential holder.
/// - If `vc.holder` does not exist, fallback to all `credentialSubject.[i].id`.
/// - The credential holder (or one of the subject IDs) must match the VP holder.
/// - Exception: If a Delegation VC is present that authorizes the VP holder to present
///   credentials belonging to another holder, those credentials are allowed.
/// - If no holder or subject IDs exist, mark as invalid.
class HolderBindingVerifier implements VpVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation vp) async {
    final vpHolderDid = vp.holder.id.toString();
    final errors = <String>[];

    // First pass: collect delegation VCs and track external holder VCs
    // Map: issuer (delegator) DID -> Set of authorized VC IDs
    final delegationMap = <String, Set<String>>{};
    // Map: external holder DID -> List of VC IDs held by them
    final externalHolderVcIdsMap = <String, List<String>>{};
    
    for (final vc in vp.verifiableCredential) {
      if (vc is! LdVcDataModelV1) {
        continue;
      }
      
      final isDelegation = vc.type.contains(_delegationVcType);
      
      if (isDelegation) {
        // The issuer of the delegation VC is the delegator (original credential holder)
        final delegatorDid = vc.issuer.id.toString();
        
        // Verify delegation VC holder matches VP holder
        final delegationHolderId = vc.holder?.id.toString();
        if (delegationHolderId != vpHolderDid) {
          errors.add(
            'Delegation VC ${vc.id} holder $delegationHolderId does not match VP holder $vpHolderDid',
          );
          // Still track this delegation to avoid cascading "missing delegation" errors
          delegationMap[delegatorDid] = <String>{};
          continue;
        }
        
        // Get the delegated credentials list from credentialSubject
        final subject = vc.credentialSubject.isNotEmpty 
            ? vc.credentialSubject.first 
            : <String, dynamic>{};
        
        final delegationLevel = subject['delegationLevel'] as String? ?? 'restricted';
        
        // For 'full' delegation, all credentials from this delegator are allowed
        if (delegationLevel == 'full') {
          delegationMap[delegatorDid] = {}; // Empty set means all credentials allowed
        } else if (delegationLevel == 'restricted') {
          // For 'restricted' delegation, collect specific credential IDs
          final credentialsList = subject['credentials'] as List<dynamic>? ?? [];
          final authorizedIds = credentialsList
              .whereType<Map<String, dynamic>>()
              .map((cred) => cred['id'] as String?)
              .whereType<String>()
              .toSet();
          
          delegationMap[delegatorDid] = authorizedIds;
        } else {
          errors.add('Invalid delegation level: $delegationLevel');
          // Still track this delegation to avoid cascading "missing delegation" errors
          delegationMap[delegatorDid] = <String>{};
        }
      } else {
        // Track VCs with external holders (holder != VP holder)
        // Only track if VC has explicit holder field
        final vcHolderDid = vc.holder?.id.toString();
        if (vcHolderDid != null && vcHolderDid != vpHolderDid) {
          final vcId = vc.id?.toString() ?? '<unknown-vc>';
          externalHolderVcIdsMap
              .putIfAbsent(vcHolderDid, () => [])
              .add(vcId);
        }
      }
    }

    // Second pass: verify all external holder VCs have corresponding delegation VCs
    for (final externalHolderDid in externalHolderVcIdsMap.keys) {
      final vcIds = externalHolderVcIdsMap[externalHolderDid]!;
      final delegatedIds = delegationMap[externalHolderDid];

      if (delegatedIds == null) {
        errors.add('Missing delegation VC from: $externalHolderDid');
        continue;
      }

      // Full delegation (empty set) allows all credentials
      if (delegatedIds.isEmpty) {
        continue;
      }

      // Restricted delegation - verify all VCs are in the authorized list
      final missedVcs = vcIds.where((vcId) => !delegatedIds.contains(vcId)).toList();
      if (missedVcs.isNotEmpty) {
        errors.add('Missing delegation VC IDs: ${missedVcs.join(', ')}');
      }

      final unexpectedVcs = delegatedIds.where((vcId) => !vcIds.contains(vcId)).toList();
      if (unexpectedVcs.isNotEmpty) {
        errors.add('Unexpected VCs in the Delegation VC: ${unexpectedVcs.join(', ')}');
      }
    }

    // Third pass: verify holder binding for all non-delegation VCs
    for (final vc in vp.verifiableCredential) {
      if (vc is! LdVcDataModelV1) {
        continue;
      }
      
      // Skip delegation VCs (already validated)
      if (vc.type.contains(_delegationVcType)) {
        continue;
      }
      
      final vcId = vc.id?.toString() ?? '<unknown-vc>';
      final holderId = vc.holder?.id.toString();

      if (holderId != null && holderId.isNotEmpty) {
        // Holder binding already verified in second pass for external holders
        if (holderId != vpHolderDid) {
          // Only add error if not already reported in second pass
          if (!externalHolderVcIdsMap.containsKey(holderId)) {
            errors.add(
              'VC $vcId holder $holderId does not match VP holder $vpHolderDid',
            );
          }
        }
      } else {
        // VC has no holder field, check credentialSubject.id
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
          continue;
        }
        
        // Check if any of the subject IDs is delegated
        bool isDelegated = false;
        for (final subjectId in subjectIds) {
          if (externalHolderVcIdsMap.containsKey(subjectId)) {
            final delegatedVcIds = externalHolderVcIdsMap[subjectId]!;
            if (delegatedVcIds.contains(vcId)) {
              isDelegated = true;
              break;
            }
          }
        }
        
        // Only check holder binding if not delegated
        if (!isDelegated && !subjectIds.contains(vpHolderDid)) {
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
