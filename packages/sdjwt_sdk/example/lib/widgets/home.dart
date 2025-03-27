import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:sdjwt_demo/consts.dart';
import 'package:sdjwt_sdk/sdjwt_sdk.dart';

import '../models.dart';
import '../utils.dart';
import 'widgets.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  Map<String, bool> selectedDisclosures = {};
  String sdJwt = '';
  String decodedSdJwt = '';
  String verificationDetails = '';
  String verificationResult = '';
  KeyType selectedKeyType = KeyType.rsa;
  SdJwtSignAlgorithm selectedAlgorithm = SdJwtSignAlgorithm.rs256;
  int? selectedSampleCaseIndex;

  final claimsTextController = TextEditingController(text: claimsText);
  final privateKeyTextController =
      TextEditingController(text: privateRsaKeyText);
  final publicKeyTextController = TextEditingController(text: publicRsaKeyText);

  @override
  void initState() {
    super.initState();
    parseClaims();
    loadSampleCase(0);
  }

  @override
  void dispose() {
    claimsTextController.dispose();
    privateKeyTextController.dispose();
    publicKeyTextController.dispose();
    super.dispose();
  }

  void parseClaims() {
    try {
      final claims =
          json.decode(claimsTextController.text) as Map<String, dynamic>;
      Map<String, bool> newSelectedDisclosures = {};
      flattenClaims(claims).forEach((key, value) {
        newSelectedDisclosures[key] = false;
      });
      setState(() {
        selectedDisclosures = newSelectedDisclosures;
      });
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Invalid JSON: $e')),
      );
    }
  }

  void loadSampleCase(int index) {
    final sampleCase = SampleCases.predefined[index];
    setState(() {
      selectedSampleCaseIndex = index;
      claimsTextController.text = prettyPrint(sampleCase.claims);
    });
    parseClaims();
  }

  void toggleDisclosure(String key) {
    setState(() {
      selectedDisclosures[key] = !(selectedDisclosures[key] ?? false);
    });
  }

  void updateKeyType(KeyType? type) {
    if (type != null) {
      setState(() {
        selectedKeyType = type;
        selectedAlgorithm = type == KeyType.rsa
            ? SdJwtSignAlgorithm.rs256
            : SdJwtSignAlgorithm.es256;
      });
    }
  }

  void navigateToResultsPage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => SecondPage(
          sdJwt: sdJwt,
          decodedSdJwt: decodedSdJwt,
          verificationResult: verificationResult,
          verificationDetails: verificationDetails,
          privateKey: privateKeyTextController.text,
          publicKey: publicKeyTextController.text,
          algorithm: selectedAlgorithm,
          selectedDisclosures: selectedDisclosures,
          claims: claimsTextController.text,
          selectedKeyType: selectedKeyType,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Selective Disclosure JWT Demo'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            KeyInputSection(
              privateKeyController: privateKeyTextController,
              publicKeyController: publicKeyTextController,
              selectedKeyType: selectedKeyType,
              onKeyTypeChanged: updateKeyType,
            ),
            const SizedBox(height: 16),
            ClaimsInputSection(
              claimsController: claimsTextController,
              onParseClaims: parseClaims,
            ),
            const SizedBox(height: 16),
            DisclosuresSection(
              selectedDisclosures: selectedDisclosures,
              onToggleDisclosure: toggleDisclosure,
            ),
            const SizedBox(height: 16),
            SampleCasesSection(
              selectedSampleCaseIndex: selectedSampleCaseIndex,
              onSampleCaseSelected: loadSampleCase,
              sampleCases: SampleCases.predefined,
            ),
            const SizedBox(height: 24),
            ContinueButton(onPressed: navigateToResultsPage),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}
