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

import com.zepben.vertxutils.resttesting.TestHttpServer
import com.zepben.vertxutils.routing.RouteVersionUtils
import io.netty.handler.codec.http.HttpResponseStatus
import io.restassured.RestAssured
import io.vertx.core.json.JsonObject
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AuthConfigRouteTest {
    private var server: TestHttpServer? = null
    private var port = 8080

    @BeforeEach
    fun before() {
        server = TestHttpServer().addRoutes(
            RouteVersionUtils.forVersion(
                AvailableRoute.values(),
                2
            ) { routeFactory(it, "test-aud", "test-domain", "test-alg") }
        )
        port = server!!.listen()
    }

    @Test
    fun testHandle() {
        val expectedResponse: String = JsonObject().apply {
            put("aud", "test-aud")
            put("dom", "test-domain")
            put("alg", "test-alg")
        }.encode()

        val response = RestAssured.given()
            .port(port)["/auth"]
            .then()
            .statusCode(HttpResponseStatus.OK.code())
            .extract().body().asString()

        assertThat(response, equalTo(expectedResponse))
    }
}
