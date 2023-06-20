/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:test/test.dart';
import 'package:tiki_idp/rsa/rsa.dart';
import 'package:tiki_idp/rsa/rsa.dart' as RSA;
import 'package:tiki_idp/rsa/rsa_private_key.dart';
import 'package:tiki_idp/rsa/rsa_public_key.dart';

void main() {
  RsaKeyPair generate() {
    final keyGen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64),
          secureRandom()));

    AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = keyGen.generateKeyPair();
    RSAPublicKey publicKey = keyPair.publicKey as RSAPublicKey;
    RSAPrivateKey privateKey = keyPair.privateKey as RSAPrivateKey;

    return RsaKeyPair(
        RsaPublicKey(publicKey.modulus!, publicKey.publicExponent!),
        RsaPrivateKey(privateKey.modulus!, privateKey.privateExponent!,
            privateKey.p, privateKey.q));
  }

  group('RSA Tests', () {
    test('Encode - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      String publicKeyEncoded = keyPair.publicKey.encode();
      String privateKeyEncoded = keyPair.privateKey.encode();
      expect(publicKeyEncoded.isNotEmpty, true);
      expect(privateKeyEncoded.isNotEmpty, true);
    });

    test('PublicKey Decode - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      String publicKeyEncoded = keyPair.publicKey.encode();
      RsaPublicKey publicKeyDecoded = RsaPublicKey.decode(publicKeyEncoded);
      expect(publicKeyDecoded.exponent, keyPair.publicKey.exponent);
      expect(publicKeyDecoded.modulus, keyPair.publicKey.modulus);
    });

    test('PrivateKey Decode - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      String privateKeyEncoded = keyPair.privateKey.encode();
      RsaPrivateKey privateKeyDecoded = RsaPrivateKey.decode(privateKeyEncoded);

      expect(privateKeyDecoded.modulus, keyPair.privateKey.modulus);
      expect(privateKeyDecoded.exponent, keyPair.privateKey.exponent);
      expect(privateKeyDecoded.privateExponent,
          keyPair.privateKey.privateExponent);
      expect(
          privateKeyDecoded.publicExponent, keyPair.privateKey.publicExponent);
      expect(privateKeyDecoded.p, keyPair.privateKey.p);
      expect(privateKeyDecoded.q, keyPair.privateKey.q);
    });

    test('Encrypt - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      Uint8List cipherText = RSA.encrypt(
          keyPair.publicKey, Uint8List.fromList(utf8.encode("hello world")));
      String cipherTextString = String.fromCharCodes(cipherText);

      expect(cipherText.isNotEmpty, true);
      expect(cipherTextString.isNotEmpty, true);
    });

    test('Decrypt Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      String plainText = "hello world";
      Uint8List cipherText = RSA.encrypt(
          keyPair.publicKey, Uint8List.fromList(utf8.encode(plainText)));
      String result = utf8.decode(RSA.decrypt(keyPair.privateKey, cipherText));
      expect(result, plainText);
    });

    test('Sign - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      String message = "hello world";
      Uint8List signature = RSA.sign(
          keyPair.privateKey, Uint8List.fromList(utf8.encode(message)));
      expect(signature.isNotEmpty, true);
    });

    test('Verify - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair = generate();
      String message = "hello world";
      Uint8List signature = RSA.sign(
          keyPair.privateKey, Uint8List.fromList(utf8.encode(message)));
      bool verify = RSA.verify(keyPair.publicKey,
          Uint8List.fromList(utf8.encode(message)), signature);
      expect(verify, true);
    });
  });
}
