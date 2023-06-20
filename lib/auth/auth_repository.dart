/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'auth_model_rsp.dart';

class AuthRepository {
  static const url = 'https://auth.l0.mytiki.com';
  static const grantPath = '/api/latest/oauth/token';
  final Uri _serviceUri = Uri.parse(url);

  Future<AuthModelRsp> grant(String? clientId, String scope,
      {String? clientSecret}) async {
    http.Response rsp = await http.post(
        _serviceUri.replace(path: grantPath, queryParameters: {
          'grant_type': 'client_credentials',
          'scope': scope,
          'client_id': clientId,
          'client_secret': clientSecret
        }),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json"
        });

    if (rsp.statusCode == 200) {
      return AuthModelRsp.fromMap(jsonDecode(rsp.body));
    } else {
      throw HttpException('HTTP Error ${rsp.statusCode}: ${rsp.body}');
    }
  }
}
