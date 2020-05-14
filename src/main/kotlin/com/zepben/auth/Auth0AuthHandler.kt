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
import io.vertx.core.AsyncResult
import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.http.HttpHeaders
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.impl.AuthHandlerImpl
import io.vertx.ext.web.handler.impl.HttpStatusException

enum class Type(private val label: String) {
    BASIC("Basic"), DIGEST("Digest"), BEARER("Bearer"),  // these have no known implementation
    HOBA("HOBA"), MUTUAL("Mutual"), NEGOTIATE("Negotiate"), OAUTH("OAuth"), SCRAM_SHA_1("SCRAM-SHA-1"), SCRAM_SHA_256("SCRAM-SHA-256");

    fun labelIs(other: String?): Boolean {
        return label.equals(other, ignoreCase = true)
    }

}

class Auth0AuthHandler(authProvider: JWTAuthProvider,
                       requiredClaims: Set<String>,
                       private val type: Type,
                       private val skip: String? = null) :
    AuthHandlerImpl(authProvider) {

    init {
        addAuthorities(requiredClaims)
    }

    companion object {
        @JvmStatic
        val UNAUTHORIZED = HttpStatusException(401)

        @JvmStatic
        val BAD_REQUEST = HttpStatusException(400)
    }

    private fun parseAuthorization(
        ctx: RoutingContext,
        handler: Handler<AsyncResult<String?>>
    ) {
        val request = ctx.request()
        val authorization = request.headers()[HttpHeaders.AUTHORIZATION] ?: run { handler.handle(Future.failedFuture(UNAUTHORIZED)); return }

        try {
            val idx = authorization.indexOf(' ')
            if (idx <= 0) {
                handler.handle(Future.failedFuture(BAD_REQUEST))
                return
            }
            if (!type.labelIs(authorization.substring(0, idx))) {
                handler.handle(Future.failedFuture(UNAUTHORIZED))
                return
            }
            handler.handle(Future.succeededFuture(authorization.substring(idx + 1)))
        } catch (e: RuntimeException) {
            handler.handle(Future.failedFuture(e))
        }
    }

    override fun parseCredentials(context: RoutingContext?, handler: Handler<AsyncResult<JsonObject>>?) {

        if (skip != null && context!!.normalisedPath().startsWith(skip)) {
            context.next()
            return
        }

        parseAuthorization(
            context!!,
            Handler { parseAuthorization: AsyncResult<String?> ->
                if (parseAuthorization.failed()) {
                    handler!!.handle(Future.failedFuture(parseAuthorization.cause()))
                    return@Handler
                }
                handler!!.handle(
                    Future.succeededFuture(
                        JsonObject().put("jwt", parseAuthorization.result())
                    )
                )
            }
        )
    }

}
