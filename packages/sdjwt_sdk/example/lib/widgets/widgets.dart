// ignore_for_file: use_build_context_synchronously

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:sdjwt_demo/consts.dart';
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

import '../models.dart';
import '../utils.dart';

class SecondPage extends StatefulWidget {
  final String sdJwt;
  final String decodedSdJwt;
  final String verificationResult;
  final String verificationDetails;
  final String privateKey;
  final String publicKey;
  final SdJwtSignAlgorithm algorithm;
  final Map<String, bool> selectedDisclosures;
  final String claims;
  final KeyType selectedKeyType;

  const SecondPage({
    super.key,
    required this.sdJwt,
    required this.decodedSdJwt,
    required this.verificationResult,
    required this.verificationDetails,
    required this.privateKey,
    required this.publicKey,
    required this.algorithm,
    required this.selectedDisclosures,
    required this.claims,
    required this.selectedKeyType,
  });

  @override
  State<SecondPage> createState() => _SecondPageState();
}

class _SecondPageState extends State<SecondPage> {
  String sdJwt = '';
  String decodedSdJwt = '';
  String verificationResult = '';
  String verificationDetails = '';

  @override
  void initState() {
    super.initState();
    sdJwt = widget.sdJwt;
    decodedSdJwt = widget.decodedSdJwt;
    verificationResult = widget.verificationResult;
    verificationDetails = widget.verificationDetails;
  }

  Future<void> verify() async {
    try {
      final results = await verifySdJwt(
        keyMaterial: widget.publicKey,
        algorithm: widget.algorithm,
        sdJwt: sdJwt,
      );

      setState(() {
        verificationResult = results['verificationResult'] ?? '';
        verificationDetails = results['verificationDetails'] ?? '';
      });
    } catch (e) {
      setState(() {
        verificationResult = 'Verification: Failed';
        verificationDetails = 'Error: ${e.toString()}';
      });

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Verification failed: ${e.toString()}')),
      );
    }
  }

  void resetAll() {
    setState(() {
      sdJwt = widget.sdJwt;
      decodedSdJwt = widget.decodedSdJwt;
      verificationResult = widget.verificationResult;
      verificationDetails = widget.verificationDetails;
    });
  }

  Future<void> sign() async {
    try {
      final keyMaterial = widget.privateKey.trim();

      final results = await signSdJwt(
        keyMaterial: keyMaterial,
        algorithm: widget.algorithm,
        claims: json.decode(widget.claims),
        selectedDisclosures: widget.selectedDisclosures,
      );

      setState(() {
        sdJwt = results['sdJwt'] ?? '';
        decodedSdJwt = results['decodedSdJwt'] ?? '';
        verificationResult =
            'Signed with ${widget.selectedKeyType.toDisplayString()}';
      });
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Signing failed: ${e.toString()}')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('SD-JWT Results'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 16),
            ActionButtons(
              onSignSdJwt: sign,
              onVerifySdJwt: verify,
              onResetAll: resetAll,
            ),
            Card(
              child: Container(
                width: MediaQuery.of(context).size.width,
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Output',
                      style:
                          TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 16),
                    if (verificationResult.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 16),
                        child: Text(
                          verificationResult,
                          key: const Key('verification_result_text'),
                          style: const TextStyle(fontWeight: FontWeight.bold),
                        ),
                      ),
                    if (sdJwt.isNotEmpty) ...[
                      const Text('SD-JWT:'),
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Colors.grey[200],
                          borderRadius: BorderRadius.circular(4),
                        ),
                        width: double.infinity,
                        child: SingleChildScrollView(
                          scrollDirection: Axis.horizontal,
                          child: SelectableText(
                            formatSdJwt(sdJwt),
                            key: const Key('sd_jwt_text'),
                            style: const TextStyle(fontFamily: 'monospace'),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                    ],
                    if (decodedSdJwt.isNotEmpty) ...[
                      const Text('Decoded SD-JWT:'),
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Colors.grey[200],
                          borderRadius: BorderRadius.circular(4),
                        ),
                        width: double.infinity,
                        height: 200,
                        child: SingleChildScrollView(
                          child: SelectableText(
                            decodedSdJwt,
                            key: const Key('decoded_sd_jwt_text'),
                            style: const TextStyle(fontFamily: 'monospace'),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                    ],
                    if (verificationDetails.isNotEmpty) ...[
                      const Text('Verification Details:'),
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Colors.grey[200],
                          borderRadius: BorderRadius.circular(4),
                        ),
                        width: double.infinity,
                        height: 150,
                        child: SingleChildScrollView(
                          child: SelectableText(
                            verificationDetails,
                            key: const Key('verification_details_text'),
                            style: const TextStyle(fontFamily: 'monospace'),
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            Center(
              child: ElevatedButton.icon(
                key: const Key('back_to_editor_button'),
                onPressed: () => Navigator.of(context).pop(),
                icon: const Icon(Icons.arrow_back),
                label: const Text('Back to Editor'),
                style: ElevatedButton.styleFrom(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
                  textStyle: const TextStyle(
                      fontSize: 16, fontWeight: FontWeight.bold),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                  minimumSize: const Size(200, 50),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class KeyInputSection extends StatelessWidget {
  final TextEditingController privateKeyController;
  final TextEditingController publicKeyController;
  final KeyType selectedKeyType;
  final Function(KeyType?) onKeyTypeChanged;

  const KeyInputSection({
    super.key,
    required this.privateKeyController,
    required this.publicKeyController,
    required this.selectedKeyType,
    required this.onKeyTypeChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Key Settings',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: RadioListTile<KeyType>(
                    title: const Text('RSA'),
                    value: KeyType.rsa,
                    groupValue: selectedKeyType,
                    onChanged: (value) {
                      onKeyTypeChanged(value);
                      privateKeyController.text = privateRsaKeyText;
                      publicKeyController.text = publicRsaKeyText;
                    },
                  ),
                ),
                Expanded(
                  child: RadioListTile<KeyType>(
                    title: const Text('ECDSA'),
                    value: KeyType.ecdsa,
                    groupValue: selectedKeyType,
                    onChanged: (value) {
                      onKeyTypeChanged(value);
                      privateKeyController.text = privateEcdsaKeyText;
                      publicKeyController.text = publicEcdsaKeyText;
                    },
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            TextField(
              controller: privateKeyController,
              decoration: InputDecoration(
                labelText: 'Private Key',
                border: OutlineInputBorder(),
                suffix: IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: privateKeyController.clear,
                ),
              ),
              maxLines: 3,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: publicKeyController,
              decoration: InputDecoration(
                labelText: 'Public Key',
                border: OutlineInputBorder(),
                suffix: IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: publicKeyController.clear,
                ),
              ),
              maxLines: 3,
            ),
          ],
        ),
      ),
    );
  }
}

class ClaimsInputSection extends StatelessWidget {
  final TextEditingController claimsController;
  final VoidCallback onParseClaims;

  const ClaimsInputSection({
    super.key,
    required this.claimsController,
    required this.onParseClaims,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Claims',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: claimsController,
              decoration: const InputDecoration(
                labelText: 'JSON Claims',
                border: OutlineInputBorder(),
              ),
              maxLines: 5,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: onParseClaims,
              child: const Text('Parse Claims'),
            ),
          ],
        ),
      ),
    );
  }
}

class DisclosuresSection extends StatelessWidget {
  final Map<String, bool> selectedDisclosures;
  final Function(String) onToggleDisclosure;

  const DisclosuresSection({
    super.key,
    required this.selectedDisclosures,
    required this.onToggleDisclosure,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Selective Disclosures',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            if (selectedDisclosures.isEmpty)
              const Text('No claims available. Parse claims first.')
            else
              Column(
                children: selectedDisclosures.keys.map((key) {
                  return CheckboxListTile(
                    title: Text(key),
                    value: selectedDisclosures[key],
                    onChanged: (_) => onToggleDisclosure(key),
                  );
                }).toList(),
              ),
          ],
        ),
      ),
    );
  }
}

class ActionButtons extends StatelessWidget {
  final VoidCallback onSignSdJwt;
  final VoidCallback onVerifySdJwt;
  final VoidCallback onResetAll;

  const ActionButtons({
    super.key,
    required this.onSignSdJwt,
    required this.onVerifySdJwt,
    required this.onResetAll,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                const Icon(Icons.bolt_outlined),
                const SizedBox(width: 8),
                const Text(
                  'Actions',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const Spacer(),
                Tooltip(
                  message: 'These actions will process your SD-JWT',
                  child: const Icon(Icons.info_outline, size: 18),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  flex: 2,
                  child: ElevatedButton.icon(
                    key: const Key('sign_sd_jwt_button'),
                    onPressed: onSignSdJwt,
                    icon: const Icon(Icons.create),
                    label: const Text('Sign SD-JWT'),
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  flex: 2,
                  child: ElevatedButton.icon(
                    key: const Key('verify_sd_jwt_button'),
                    onPressed: onVerifySdJwt,
                    icon: const Icon(Icons.verified),
                    label: const Text('Verify SD-JWT'),
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            ElevatedButton.icon(
              key: const Key('reset_button'),
              onPressed: onResetAll,
              icon: const Icon(Icons.refresh),
              label: const Text('Reset'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class SampleCasesSection extends StatelessWidget {
  final int? selectedSampleCaseIndex;
  final Function(int) onSampleCaseSelected;
  final List<SampleCase> sampleCases;

  const SampleCasesSection({
    super.key,
    required this.selectedSampleCaseIndex,
    required this.onSampleCaseSelected,
    required this.sampleCases,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Sample Cases',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 15),
            Column(
              children: [
                for (var i = 0; i < sampleCases.length; i++)
                  RadioListTile<int>(
                    title: Text(sampleCases[i].name),
                    value: i,
                    groupValue: selectedSampleCaseIndex,
                    onChanged: (int? value) {
                      if (value != null) {
                        onSampleCaseSelected(value);
                      }
                    },
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class ContinueButton extends StatelessWidget {
  final VoidCallback onPressed;

  const ContinueButton({
    super.key,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return Center(
      child: ElevatedButton.icon(
        key: const Key('continue_button'),
        onPressed: onPressed,
        icon: const Icon(Icons.arrow_forward),
        label: const Text('Continue'),
        style: ElevatedButton.styleFrom(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          minimumSize: const Size(200, 50),
        ),
      ),
    );
  }
}
