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

import com.zepben.auth.vertx.JWTAuthProvider
import com.zepben.vertxutils.routing.Route
import com.zepben.vertxutils.routing.RouteVersion
import com.zepben.vertxutils.routing.VersionableRoute
import io.vertx.core.http.HttpMethod

/**
 * A route for authenticating users based on Auth0 JWTs.
 */
class AuthRoute {
    companion object {

        /**
         * Creates a route that has a handler implementing [io.vertx.ext.web.handler.AuthHandler] that supports
         * Auth0 JWTs using [JWTAuthProvider] and [JWTAuthenticator].
         *
         * @param availableRoute The [AvailableRoute] for API version management.
         * @param path The path the [Route] should be built on
         * @param audience The audience required for JWT authentication
         * @param issuer The issuer domain required for JWT authentication
         * @param requiredClaims The claims required for the JWT for authorisation.
         */
        @JvmOverloads
        @JvmStatic
        fun routeFactory(
            path: String,
            audience: String,
            issuer: String,
            requiredClaims: Iterable<String> = emptySet(),
            isRegexPath: Boolean = false
        ): (AvailableRoute) -> Route =
            { availableRoute ->
                when (availableRoute) {
                    AvailableRoute.AUTH ->
                        Route.builder()
                            .method(HttpMethod.GET)
                            .path(path)
                            .hasRegexPath(isRegexPath)
                            .addHandler(
                                Auth0AuthHandler(
                                    JWTAuthProvider(JWTAuthenticator(audience, issuer)),
                                    mutableSetOf<String>().apply { addAll(requiredClaims) },
                                    Type.BEARER
                                )
                            )
                            .build()
                }
            }
    }

    enum class AvailableRoute(private val rv: RouteVersion) : VersionableRoute {
        AUTH(RouteVersion.since(0));

        override fun routeVersion(): RouteVersion {
            return rv
        }
    }
}
