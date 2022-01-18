// Copyright 2019 Zeppelin Bend Pty Ltd
// This file is part of zepben-auth.
//
// zepben-auth is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// zepben-auth is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with zepben-auth.  If not, see <https://www.gnu.org/licenses/>.


package com.zepben.auth

import com.auth0.jwt.exceptions.*
import com.zepben.auth.JWTAuthoriser.authorise
import com.zepben.testutils.auth.*
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.instanceOf
import org.junit.jupiter.api.Test

class JWTAuthenticatorTest {

    @Test
    fun testAuth() {
        var ta = JWTAuthenticator("https://fake-aud/", "issuer", MockJwksUrlProvider())
        var authResp = ta.authenticate(TOKEN)
        assertThat(authResp.statusCode, equalTo(StatusCode.OK))
        val successfulToken = authResp.token!!
        authResp = authorise(successfulToken, "write:network")
        assertThat(authResp.statusCode, equalTo(StatusCode.OK))

        authResp = authorise(successfulToken, "bacon")
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.message, equalTo("Token was missing required claim bacon"))

        authResp = ta.authenticate("broken")
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(JWTDecodeException::class.java))

        authResp = ta.authenticate(TOKEN_RS512)
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(AlgorithmMismatchException::class.java))

        authResp = ta.authenticate(TOKEN_BAD_SIG)
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(SignatureVerificationException::class.java))

        authResp = ta.authenticate(TOKEN_EXPIRED)
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(TokenExpiredException::class.java))

        ta = JWTAuthenticator("https://wrong-aud/", "issuer", MockJwksUrlProvider())
        authResp = ta.authenticate(TOKEN)
        assertThat(authResp.statusCode, equalTo(StatusCode.PERMISSION_DENIED))
        assertThat(authResp.cause, instanceOf(InvalidClaimException::class.java))
        assertThat(authResp.message, equalTo("The Claim 'aud' value doesn't contain the required audience."))

        ta = JWTAuthenticator("https://fake-aud/", "wrong-issuer", MockJwksUrlProvider())
        authResp = ta.authenticate(TOKEN)
        assertThat(authResp.statusCode, equalTo(StatusCode.PERMISSION_DENIED))
        assertThat(authResp.cause, instanceOf(InvalidClaimException::class.java))
        assertThat(authResp.message, equalTo("The Claim 'iss' value doesn't match the required issuer."))
    }
}



