package com.example.plugins

import io.ktor.auth.*
import io.ktor.util.*
import io.ktor.auth.jwt.*
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.ConfigFactory
import io.ktor.application.*
import io.ktor.config.*
import io.ktor.response.*
import io.ktor.request.*

fun Application.configureSecurity() {
    val  config = HoconApplicationConfig(ConfigFactory.load())
    val jwtIssuer = config.property("jwt.domain").getString()
    val jwtAudience = config.property("jwt.audience").getString()
    val jwtRealm = config.property("jwt.realm").getString()
    authentication {
        jwt {
            realm = jwtRealm
            verifier(makeJwtVerifier(jwtIssuer, jwtAudience))
            validate { credential ->
                if (credential.payload.audience.contains(jwtAudience)) JWTPrincipal(credential.payload) else null
            }
        }
    }

}

private val algorithm = Algorithm.HMAC256("secret")
private fun makeJwtVerifier(issuer: String, audience: String): JWTVerifier = JWT
    .require(algorithm)
    .withAudience(audience)
    .withIssuer(issuer)
    .build()
