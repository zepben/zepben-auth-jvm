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


package com.zepben.auth.vertx

import com.zepben.auth.*
import io.vertx.core.AsyncResult
import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.AuthProvider
import io.vertx.ext.auth.User
import io.vertx.kotlin.core.json.get

/**
 * An implementation of an [AuthProvider] that performs JWT authentication with the provided [tokenAuthenticator]
 *
 * @property tokenAuthenticator The Authenticator to use for for authentication.
 */
class JWTAuthProvider(private val tokenAuthenticator: TokenAuthenticator) : AuthProvider {

    /**
     * Authenticate a client based on the provided [authInfo].
     * @param A [JsonObject] with a "jwt" entry with the JWT for this client.
     */
    override fun authenticate(authInfo: JsonObject?, resultHandler: Handler<AsyncResult<User>>) {
        val token: String? = authInfo?.get("jwt")
        val resp = tokenAuthenticator.authenticate(token)
        if (resp.statusCode !== StatusCode.OK) {
            resultHandler.handle(Future.failedFuture(resp.asHttpException()))
            return
        }

        resp.token?.let { resultHandler.handle(Future.succeededFuture(User(it))) } ?: resultHandler.handle(
            Future.failedFuture("Token was missing on successful auth - this is a bug.")
        )
    }

}
