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


package com.zepben.auth.server.grpc

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.common.StatusCode
import com.zepben.auth.server.AuthResponse
import com.zepben.auth.server.JWTAuthoriser
import com.zepben.auth.server.TokenAuthenticator
import io.grpc.*
import io.grpc.Metadata.ASCII_STRING_MARSHALLER


val AUTHORIZATION_METADATA_KEY: Metadata.Key<String> = Metadata.Key.of("Authorization", ASCII_STRING_MARSHALLER)
const val BEARER_TYPE = "Bearer"

fun statusCodeToStatus(statusCode: StatusCode): Status =
    when (statusCode) {
        StatusCode.OK -> Status.OK
        StatusCode.PERMISSION_DENIED -> Status.PERMISSION_DENIED
        StatusCode.UNAUTHENTICATED -> Status.UNAUTHENTICATED
        StatusCode.UNKNOWN -> Status.UNKNOWN
        else -> Status.UNKNOWN
    }

fun authRespToGrpcAuthResp(response: AuthResponse) =
    GrpcAuthResp(
        statusCodeToStatus(response.statusCode).withDescription(response.message).withCause(response.cause)
    )

data class GrpcAuthResp(val status: Status, val token: DecodedJWT? = null)

class AuthInterceptor(
    private val tokenAuthenticator: TokenAuthenticator,
    private val requiredScopes: Map<String, String>
) : ServerInterceptor {

    override fun <ReqT, RespT> interceptCall(
        serverCall: ServerCall<ReqT, RespT>,
        metadata: Metadata,
        serverCallHandler: ServerCallHandler<ReqT, RespT>?
    ): ServerCall.Listener<ReqT> {
        val value = metadata[AUTHORIZATION_METADATA_KEY]
        val authResp = if (value == null) {
            GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Authorization token is missing"))
        } else if (!value.startsWith(BEARER_TYPE)) {
            GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Unknown authorization type"))
        } else {
            val r = tokenAuthenticator.authenticate(value.substring(BEARER_TYPE.length).trim { it <= ' ' })
            if (r.statusCode === StatusCode.OK)
                requiredScopes[serverCall.methodDescriptor.serviceName!!]?.let {
                    authRespToGrpcAuthResp(JWTAuthoriser.authorise(r.token!!, it))
                }
                    ?: GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Server has not defined a permission scope for ${serverCall.methodDescriptor.serviceName}. This is a bug, contact the developers."))
            else
                GrpcAuthResp(statusCodeToStatus(r.statusCode).withDescription(r.message).withCause(r.cause))
        }

        if (authResp.status === Status.OK) {
            val ctx: Context = Context.current()
            return Contexts.interceptCall(ctx, serverCall, metadata, serverCallHandler)
        }
        serverCall.close(authResp.status, Metadata())
        return object : ServerCall.Listener<ReqT>() {} // no-op
    }
}


