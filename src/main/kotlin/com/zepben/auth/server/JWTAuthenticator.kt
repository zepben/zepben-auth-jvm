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


package com.zepben.auth.server

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.*
import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.common.AuthException
import com.zepben.auth.common.StatusCode
import io.vertx.ext.web.handler.impl.HttpStatusException
import java.security.interfaces.RSAPublicKey

const val WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json"
const val AUTHORIZATION_HEADER = "Authorization"
const val CONTENT_TYPE = "Content-Type"

data class AuthResponse(
    val statusCode: StatusCode,
    val message: String? = null,
    val cause: Throwable? = null,
    val token: DecodedJWT? = null
)

fun AuthResponse.asException(): AuthException = AuthException(statusCode.code, message)
fun AuthResponse.asHttpException(): HttpStatusException = HttpStatusException(statusCode.code, message)

interface TokenAuthenticator {
    fun authenticate(token: String?): AuthResponse
}

/**
 * A TokenAuthenticator that authenticates JWTs using a retrievable JWK
 *
 * @property audience The audience required for the token to be authenticated.
 * @property issuerDomain The domain hosting the JWKS.
 * @property jwkProvider An [UrlJwkProvider] for fetching the JWK used for authenticating JWTs.
 * @property issuer The Issuer required for the token to be authenticated. Typically is the same as [issuerDomain]. Will
 *                  default to https://<[jwksDomain]>/.
 */
open class JWTAuthenticator(
    private val audience: String,
    private val issuerDomain: String,
    private val jwkProvider: UrlJwkProvider = UrlJwkProvider(issuerDomain),
    private val issuer: String = "https://${issuerDomain}/"
): TokenAuthenticator {
    private var keys: Map<String, Jwk> = refreshJwk()

    private fun refreshJwk() = jwkProvider.all.associateBy { it.id }

    private fun getKeyFromJwk(kid: String): Jwk =
        keys[kid] ?: run {
            refreshJwk()
            keys[kid] ?: throw JwkException("Unable to find key $kid in ${issuerDomain}$WELL_KNOWN_JWKS_PATH")
        }

    override fun authenticate(token: String?): AuthResponse =
        if (token.isNullOrEmpty()) {
            AuthResponse(StatusCode.UNAUTHENTICATED, "No token was provided")
        } else {
            try {
                val decoded = JWT.decode(token)
                // Get the key ID for the key that was used to sign this key, and look it up against our stored keys.
                val rsaKey = getKeyFromJwk(decoded.getHeaderClaim("kid").asString())
                val rsaAlg = Algorithm.RSA256(rsaKey.publicKey as RSAPublicKey?, null)

                // verify token signature
                val verifier = JWT
                    .require(rsaAlg)
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .acceptLeeway(60 * 1000) // Extend valid window by 60 seconds in both directions
                    .build()
                verifier.verify(decoded)

                AuthResponse(StatusCode.OK, token = decoded)
            } catch (je: JWTDecodeException) {
                AuthResponse(StatusCode.UNAUTHENTICATED, je.message, je)
            } catch (alg: AlgorithmMismatchException) {
                AuthResponse(StatusCode.UNAUTHENTICATED, alg.message, alg)
            } catch (sig: SignatureVerificationException) {
                AuthResponse(StatusCode.UNAUTHENTICATED, sig.message, sig)
            } catch (exp: TokenExpiredException) {
                AuthResponse(StatusCode.UNAUTHENTICATED, exp.message, exp)
            } catch (claim: InvalidClaimException) {
                AuthResponse(StatusCode.PERMISSION_DENIED, claim.message, claim)
            } catch (i: IllegalArgumentException) {
                AuthResponse(StatusCode.MALFORMED_TOKEN, i.message, i)
            } catch (e: Exception) {
                AuthResponse(StatusCode.UNKNOWN, e.message, e)
            }
        }
}


