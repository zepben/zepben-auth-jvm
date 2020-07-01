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

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.StatusCode
import com.zepben.auth.JWTAuthoriser
import com.zepben.auth.asHttpException
import io.vertx.core.AsyncResult
import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.json.JsonObject
import io.vertx.core.shareddata.impl.ClusterSerializable
import io.vertx.ext.auth.AbstractUser
import io.vertx.ext.auth.AuthProvider


/**
 *
 */
class User(private val jwt: DecodedJWT) : AbstractUser(), ClusterSerializable {

    override fun doIsPermitted(claims: String?, resultHandler: Handler<AsyncResult<Boolean>>) {
        if (claims.isNullOrEmpty()) {
            resultHandler.handle(Future.failedFuture("No permission was specified"))
            return
        }

        val resp = JWTAuthoriser.authorise(jwt, claims)
        if (resp.statusCode === StatusCode.OK)
            resultHandler.handle(Future.succeededFuture(true))
        else {
            resultHandler.handle(Future.succeededFuture(false))
        }
    }

    override fun setAuthProvider(authProvider: AuthProvider?) {
        throw NotImplementedError()
    }


    override fun principal() = JsonObject(mapOf("jwt" to jwt))
}
