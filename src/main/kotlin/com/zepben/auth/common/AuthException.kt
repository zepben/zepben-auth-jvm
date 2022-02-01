package com.zepben.auth.common

class AuthException(val statusCode: Int, message: String? = null): Exception(message)