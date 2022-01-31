package com.zepben.auth

class AuthException(val statusCode: Int, message: String? = null): Exception(message)