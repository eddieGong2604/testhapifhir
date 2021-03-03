package ca.uhn.fhir.jpa.starter.token;

import io.jsonwebtoken.Claims;

public interface TokenInterpreter {

    Claims getClaimsFromToken(String jwtToken);

}
