/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:uuid/uuid.dart';

import '../auth/auth_service.dart';
import '../key/key_model.dart';
import '../key/key_service.dart';
import '../rsa/rsa.dart' as rsa;
import '../rsa/rsa_private_key.dart';
import 'registry.dart';
import 'registry_model_req.dart';
import 'registry_model_rsp.dart';
import 'registry_repository.dart';

class RegistryService {
  final KeyService _keyService;
  final RegistryRepository _repository;
  final AuthService _authService;

  RegistryService(this._keyService, this._authService)
      : _repository = RegistryRepository();

  Future<Registry> get(String id, String userKeyId) async {
    String? auth = (await _authService.token).accessToken;
    RegistryModelRsp rsp = await _repository.addresses(id,
        signature: await _signature(userKeyId), authorization: auth);
    String signKeyId = await _saveKey(rsp.signKey!);
    return Registry(signKeyId, rsp.addresses ?? []);
  }

  Future<Registry> register(String id, String address, String userKeyId,
      {String? token}) async {
    String? auth = (await _authService.token).accessToken;
    RegistryModelRsp rsp = await _repository.register(
        RegistryModelReq(id: id, address: address),
        signature: await _signature(userKeyId),
        authorization: auth,
        customerAuth: token);
    String signKeyId = await _saveKey(rsp.signKey!);
    return Registry(signKeyId, rsp.addresses ?? []);
  }

  Future<String> _signature(String keyId, {String? message}) async {
    KeyModel? keyModel = await _keyService.get(keyId);
    if (keyModel == null) throw RangeError('Missing key: $keyId');
    RsaPrivateKey key = RsaPrivateKey.decode(keyModel.key);
    message ??= const Uuid().v4();
    Uint8List signature =
        rsa.sign(key, Uint8List.fromList(utf8.encode(message)));
    return "$message.${base64.encode(key.public.bytes)}.${base64.encode(signature)}";
  }

  Future<String> _saveKey(RsaPrivateKey? key) async {
    if (key == null) throw StateError('Missing app signature key');
    Uint8List hashedKey = Digest("SHA3-256").process(key.public.bytes);
    String id = base64.encode(hashedKey);
    await _keyService.save(id, KeyModel(key.encode()));
    return id;
  }
}
