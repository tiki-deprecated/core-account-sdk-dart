/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:test/test.dart';
import 'package:tiki_idp/rsa/rsa.dart' as rsa;
import 'package:tiki_idp/rsa/rsa_private_key.dart';
import 'package:tiki_idp/rsa/rsa_public_key.dart';

import 'fixtures/rsa_fixture.dart' as fixture;

void main() {
  group('rsa Tests', () {
    test('Encode - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
      String publicKeyEncoded = keyPair.publicKey.encode();
      String privateKeyEncoded = keyPair.privateKey.encode();
      expect(publicKeyEncoded.isNotEmpty, true);
      expect(privateKeyEncoded.isNotEmpty, true);
    });

    test('PublicKey Decode - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
      String publicKeyEncoded = keyPair.publicKey.encode();
      RsaPublicKey publicKeyDecoded = RsaPublicKey.decode(publicKeyEncoded);
      expect(publicKeyDecoded.exponent, keyPair.publicKey.exponent);
      expect(publicKeyDecoded.modulus, keyPair.publicKey.modulus);
    });

    test('PrivateKey Decode - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
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
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
      Uint8List cipherText = rsa.encrypt(
          keyPair.publicKey, Uint8List.fromList(utf8.encode("hello world")));
      String cipherTextString = String.fromCharCodes(cipherText);

      expect(cipherText.isNotEmpty, true);
      expect(cipherTextString.isNotEmpty, true);
    });

    test('Decrypt Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
      String plainText = "hello world";
      Uint8List cipherText = rsa.encrypt(
          keyPair.publicKey, Uint8List.fromList(utf8.encode(plainText)));
      String result = utf8.decode(rsa.decrypt(keyPair.privateKey, cipherText));
      expect(result, plainText);
    });

    test('Sign - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
      String message = "hello world";
      Uint8List signature = rsa.sign(
          keyPair.privateKey, Uint8List.fromList(utf8.encode(message)));
      expect(signature.isNotEmpty, true);
    });

    test('Verify - Success', () async {
      AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey> keyPair =
          fixture.generate();
      String message = "hello world";
      Uint8List signature = rsa.sign(
          keyPair.privateKey, Uint8List.fromList(utf8.encode(message)));
      bool verify = rsa.verify(keyPair.publicKey,
          Uint8List.fromList(utf8.encode(message)), signature);
      expect(verify, true);
    });
  });
}
