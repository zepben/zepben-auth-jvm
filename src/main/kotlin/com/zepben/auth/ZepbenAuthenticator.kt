package com.zepben.auth

import com.auth0.jwt.JWT
import io.vertx.core.json.DecodeException
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant
import io.vertx.core.json.Json
import io.vertx.core.json.JsonObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.lang.IllegalArgumentException
import java.net.URI
import kotlin.Exception

/**
 * @property audience Audience to use when requesting tokens.
 * @property issuerDomain The domain of the token issuer.
 * @property authMethod The authentication method used by the server.
 * @property verifyCertificate Whether to verify the SSL certificate when making requests.
 * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
 *                          what you are doing. Setting it to anything other than https is a major security risk as
 *                          tokens will be sent in the clear.
 * @property tokenPath Path for requesting token from `issuer_domain`.
 * @property algorithm Algorithm used for decoding tokens. Note tokens are only decoded for checking expiry time.
 * @property tokenRequestData Data to pass in token requests.
 * @property refreshRequestData Data to pass in refresh token requests.
 */
data class ZepbenAuthenticator(
    val audience: String,
    val issuerDomain: String,
    val authMethod: AuthMethod,
    val verifyCertificate: Boolean = false,
    val issuerProtocol: String = "https",
    val tokenPath: String = "/oauth/token",
    // TODO: This isn't even used in the Python version, and it seems an algorithm isn't necessary to decode a JWT.
    val algorithm: String = "RS256",
    val tokenRequestData: JsonObject = JsonObject(),
    val refreshRequestData: JsonObject = JsonObject()
) {
    private var _accessToken: String? = null
    private val _refreshToken: String? = null
    private var _tokenExpiry: Instant = Instant.MIN
    private var _tokenType: String? = null

    private val logger: Logger = LoggerFactory.getLogger(javaClass)

    init {
        tokenRequestData.put("audience", audience)
        refreshRequestData.put("audience", audience)
    }

    /**
     * Returns a JWT access token and its type in the form of '<type> <3 part JWT>', retrieved from the configured
     * OAuth2 token provider. Throws an Exception if an access token request fails.
     */
    fun fetchToken(): String {
        if (Instant.now() > _tokenExpiry) {
            // Stored token has expired, try to refresh
            _accessToken = null
            if (!_refreshToken.isNullOrEmpty()) {
                fetchTokenAuth0(useRefresh = true)
            }

            if (_accessToken == null) {
                // If using the refresh token did not work for any reason, self._access_token will still be None.
                // and thus we must try to get a fresh access token using credentials instead.
                fetchTokenAuth0()
            }

            if (_tokenType.isNullOrEmpty() or _accessToken.isNullOrEmpty()) {
                throw Exception(
                    "Token couldn't be retrieved from ${URL(issuerProtocol, issuerDomain, tokenPath)} using " +
                    "configuration $authMethod, audience: $audience, token issuer: $issuerDomain"
                )
            }
        }

        return "$_tokenType $_accessToken"
    }

    private fun fetchTokenAuth0(useRefresh: Boolean = false) {
        // TODO: Find out how to toggle certificate validation for HttpClient
        val client = HttpClient.newBuilder().build()
        val body = if (useRefresh) refreshRequestData.toString() else tokenRequestData.toString()
        val request = HttpRequest.newBuilder()
            .uri(URL(issuerProtocol, issuerDomain, tokenPath).toURI())
            .header("content-type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200) {
            throw Exception("Token fetch failed, Error was: ${response.statusCode()} - ${response.body()}")
        }

        val data: JsonObject
        try {
            data = Json.decodeValue(response.body()) as JsonObject
        } catch (e: DecodeException) {
            throw Exception("Response did not contain valid JSON - response was: ${response.body()}")
        } catch (e: ClassCastException) {
            throw Exception("Response was not a JSON object - response was: ${response.body()}")
        }

        if (data.containsKey("error") or !data.containsKey("access_token")) {
            throw Exception(
                (data.getString("error") ?: "Access Token absent in token response") + " - " +
                (data.getString("error_description") ?: "Response was: $data")
            )
        }

        _tokenType = data.getString("token_type")
        _accessToken = data.getString("access_token")
        _tokenExpiry = JWT.decode(_accessToken)?.getClaim("exp")?.asDate()?.toInstant() ?: Instant.MIN
    }

    /**
     * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenAuthenticator`
     *
     * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
     * @param verifyCertificate: Whether to verify the certificate when making HTTPS requests. Note you should only use a trusted server
     *                           and never set this to False in a production environment.
     * @param authTypeField The field name to look up in the JSON response from the confAddress for `authenticator.authMethod`.
     * @param audienceField The field name to look up in the JSON response from the confAddress for `authenticator.authMethod`.
     * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `authenticator.authMethod`.
     *
     * @returns: A `ZepbenAuthenticator` if the server reported authentication was configured, otherwise None.
     */
    fun createAuthenticator(
        confAddress: String,
        verifyCertificate: Boolean = true,
        authTypeField: String = "authType",
        audienceField: String = "audience",
        issuerDomainField: String = "issuer"
    ): ZepbenAuthenticator? {
        // TODO: Find out how to toggle certificate validation for HttpClient
        val client = HttpClient.newBuilder().build()
        val request = HttpRequest.newBuilder().uri(URI(confAddress)).GET().build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() == 200) {
            try {
                val authConfigJson = Json.decodeValue(response.body()) as JsonObject
                val authMethod = AuthMethod.valueOf(authConfigJson.getString(authTypeField))
                if (authMethod != AuthMethod.NONE) {
                    return ZepbenAuthenticator(
                        authConfigJson.getString(audienceField),
                        authConfigJson.getString(issuerDomainField),
                        authMethod,
                        verifyCertificate
                    )
                }
            } catch (e: DecodeException) {
                throw Exception("Response did not contain valid JSON - response was: ${response.body()}")
            } catch (e: ClassCastException) {
                throw Exception("Response was not a JSON object - response was: ${response.body()}")
            }
        } else {
            throw Exception("$confAddress responded with error: ${response.statusCode()} - ${response.body()}")
        }
        return null;
    }
}
