package com.zepben.auth.common

enum class StatusCode(val code: Int) {
    // Successful
    OK(200),
    // Token was malformed
    MALFORMED_TOKEN(400),
    // Failed to authenticate
    UNAUTHENTICATED(403),
    // Failed to authenticate, token didn't have required claims
    PERMISSION_DENIED(403),
    // Resource/service not found
    NOT_FOUND(404),
    // All other errors
    UNKNOWN(500);

}