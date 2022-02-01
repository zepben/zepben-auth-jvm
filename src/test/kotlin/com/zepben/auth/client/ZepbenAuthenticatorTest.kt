package com.zepben.auth.client

import com.zepben.auth.common.AuthException
import com.zepben.auth.common.AuthMethod
import com.zepben.auth.common.StatusCode
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.AfterEach

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import com.zepben.testutils.vertx.TestHttpServer
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.mockito.Mockito.*
import com.zepben.testutils.auth.TOKEN

import java.net.http.HttpClient
import java.net.http.HttpResponse


internal class ZepbenAuthenticatorTest {
    private var server: TestHttpServer? = null
    private var port = 8080

    private val client: HttpClient = mock(HttpClient::class.java)
    private val response = mock(HttpResponse::class.java)

    @BeforeEach
    fun beforeEach() {
        server = TestHttpServer()
        port = server!!.listen()
        doReturn(response).`when`(client).send(any(), any(HttpResponse.BodyHandler::class.java))
    }

    @AfterEach
    fun afterEach() {
        server?.close()
    }

    @Test
    fun testCreateAuthenticatorSuccess() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"AUTH0\", \"audience\": \"test_audience\", \"issuer\": \"test_issuer\"}"
        ).`when`(response).body()

        val authenticator = createAuthenticator("https://testaddress", client = client)
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(authenticator?.audience, equalTo("test_audience"))
        assertThat(authenticator?.issuerDomain, equalTo("test_issuer"))
    }

    @Test
    fun testCreateAuthenticatorNoAuth() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"NONE\", \"audience\": \"\", \"issuer\": \"\"}"
        ).`when`(response).body()

        val authenticator = createAuthenticator("https://testaddress", client = client)
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(authenticator, equalTo(null))
    }

    @Test
    fun testCreateAuthenticatorBadResponse() {
        doReturn(StatusCode.NOT_FOUND.code).`when`(response).statusCode()
        doReturn("Not found").`when`(response).body()

        val exception = assertThrows(AuthException::class.java) {
            createAuthenticator("https://testaddress", client = client)
        }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.NOT_FOUND.code))
        assertThat(exception.message, equalTo("https://testaddress responded with error: 404 - Not found"))
    }

    @Test
    fun testCreateAuthenticatorMissingJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("test text").`when`(response).body()

        val exception = assertThrows(AuthException::class.java) {
            createAuthenticator("https://testaddress", client = client)
        }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.OK.code))
        assertThat(exception.message, equalTo("Expected JSON response from https://testaddress, but got: test text."))
    }

    @Test
    fun testCreateAuthenticatorNonObjectJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("[\"authType\"]").`when`(response).body()

        val exception = assertThrows(AuthException::class.java) {
            createAuthenticator("https://testaddress", client = client)
        }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.OK.code))
        assertThat(
            exception.message,
            equalTo("Expected JSON object from https://testaddress, but got: [\"authType\"].")
        )
    }

    @Test
    fun testFetchTokenSuccessful() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, times(0)).send(any(), any(HttpResponse.BodyHandler::class.java))
        val token = authenticator.fetchToken()
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(token, equalTo("Bearer $TOKEN"))
    }

    @Test
    fun testFetchTokenThrowsExceptionOnBadResponse() {
        doReturn(StatusCode.NOT_FOUND.code).`when`(response).statusCode()
        doReturn("test text").`when`(response).body()

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, times(0)).send(any(), any(HttpResponse.BodyHandler::class.java))
        val exception = assertThrows(AuthException::class.java) { authenticator.fetchToken() }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.NOT_FOUND.code))
        assertThat(exception.message, equalTo("Token fetch failed, Error was: 404 - test text"))
    }

    @Test
    fun testFetchTokenThrowsExceptionOnMissingJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("test text").`when`(response).body()

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, times(0)).send(any(), any(HttpResponse.BodyHandler::class.java))
        val exception = assertThrows(AuthException::class.java) { authenticator.fetchToken() }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.OK.code))
        assertThat(exception.message, equalTo("Response did not contain valid JSON - response was: test text"))
    }

    @Test
    fun testFetchTokenThrowsExceptionOnNonObjectJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("[\"test text\"]").`when`(response).body()

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, times(0)).send(any(), any(HttpResponse.BodyHandler::class.java))
        val exception = assertThrows(AuthException::class.java) { authenticator.fetchToken() }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.OK.code))
        assertThat(exception.message, equalTo("Response was not a JSON object - response was: [\"test text\"]"))
    }

    @Test
    fun testFetchTokenThrowsExceptionOnMissingAccessToken() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"test\":\"fail\"}").`when`(response).body()

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, times(0)).send(any(), any(HttpResponse.BodyHandler::class.java))
        val exception = assertThrows(AuthException::class.java) { authenticator.fetchToken() }
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(exception.statusCode, equalTo(StatusCode.OK.code))
        assertThat(
            exception.message,
            equalTo("Access Token absent in token response - Response was: {\"test\":\"fail\"}")
        )
    }

    @Test
    fun testFetchTokenSuccessfulUsingRefresh() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"access_token\":\"$TOKEN\", \"refresh_token\": \"test_refresh_token\", \"token_type\":\"Bearer\"}"
        ).`when`(response).body()

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client,
            _refreshToken = "test_refresh_token"
        )
        verify(client, times(0)).send(any(), any(HttpResponse.BodyHandler::class.java))
        val token = authenticator.fetchToken()
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(token, equalTo("Bearer $TOKEN"))
    }
}