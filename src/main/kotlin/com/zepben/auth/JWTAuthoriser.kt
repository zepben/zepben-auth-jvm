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

import com.auth0.jwt.interfaces.DecodedJWT

object JWTAuthoriser {
    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaim: String): AuthResponse {
        val permissions = token.getClaim("permissions").asList(String::class.java).toHashSet()
        if (requiredClaim in permissions)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(StatusCode.UNAUTHENTICATED, "Token was missing required claim $requiredClaim")
    }

    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaims: Set<String>): AuthResponse {
        val permissions = token.getClaim("permissions").asList(String::class.java).toHashSet()
        if (permissions.intersect(requiredClaims).size == requiredClaims.size)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(
            StatusCode.UNAUTHENTICATED,
            "Token was missing a required claim. Had [${permissions.joinToString(", ")}] but needed [${requiredClaims.joinToString(
                ", "
            )}]"
        )
    }
}
