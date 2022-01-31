package com.zepben.auth

import com.zepben.vertxutils.routing.RouteVersionUtils
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.extension.RegisterExtension

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import com.zepben.testutils.junit.SystemLogExtension
import com.zepben.testutils.vertx.TestHttpServer
import io.restassured.http.ContentType
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import com.zepben.vertxutils.routing.RouteVersionUtils.forVersion
import io.restassured.RestAssured.given
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.core.IsEqual.equalTo
import org.mockito.Mockito.*
import com.zepben.testutils.auth.TOKEN

import java.net.http.HttpClient
import java.net.http.HttpResponse


internal class ZepbenAuthenticatorTest {
    private var server: TestHttpServer? = null
    private var port = 8080

    val client = mock(HttpClient::class.java)

    @BeforeEach
    fun beforeEach() {
        server = TestHttpServer()
        port = server!!.listen()
    }

    @AfterEach
    fun afterEach() {
        server?.close()
    }

    @Test
    fun testCreateAuthenticatorSuccess() {
        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "test_issuer",
            authMethod = AuthMethod.AUTH0
        )
        assertEquals(authenticator.audience, "test_audience")
        assertEquals(authenticator.issuerDomain, "test_issuer")
    }

    @Test
    fun testCreateAuthenticatorNoAuth() {

    }

    @Test
    fun testFetchTokenSuccessful() {
        val response = mock(HttpResponse::class.java)
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()
        doReturn(response).`when`(client).send(any(), any(HttpResponse.BodyHandler::class.java))

        val authenticator = ZepbenAuthenticator(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        val token = authenticator.fetchToken()
        verify(client, times(1)).send(any(), any(HttpResponse.BodyHandler::class.java))
        assertThat(token, equalTo("Bearer $TOKEN"))
    }

}