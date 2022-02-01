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

import com.zepben.vertxutils.routing.Respond
import com.zepben.vertxutils.routing.Route
import com.zepben.vertxutils.routing.RouteVersion
import com.zepben.vertxutils.routing.VersionableRoute
import io.netty.handler.codec.http.HttpResponseStatus
import io.vertx.core.Handler
import io.vertx.core.http.HttpMethod
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext

private data class AuthConfigResponse(val aud: String, val dom: String, val alg: String)

fun routeFactory(availableRoute: AvailableRoute, audience: String, domain: String, algorithm: String = "RS256"): Route =
    when (availableRoute) {
        AvailableRoute.AUTH_CONFIG ->
            Route.builder()
                .method(HttpMethod.GET)
                .path("/auth")
                .addHandler(AuthConfigRoute(audience, domain, algorithm))
                .build()
        else -> throw IllegalArgumentException("Invalid Route")
    }

enum class AvailableRoute(private val rv: RouteVersion) : VersionableRoute {
    AUTH_CONFIG(RouteVersion.since(2));

    override fun routeVersion(): RouteVersion {
        return rv
    }
}

class AuthConfigRoute(audience: String, domain: String, algorithm: String) : Handler<RoutingContext> {
    private val json: JsonObject = JsonObject.mapFrom(AuthConfigResponse(audience, domain, algorithm))

    override fun handle(event: RoutingContext?) {
        Respond.withJson(event, HttpResponseStatus.OK, json.encode())
    }
}
