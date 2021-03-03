package ca.uhn.fhir.jpa.starter.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Data
public class TokenInterpreterImpl implements TokenInterpreter {

    @Value("${jwt.secret-key}")
    private String secretKeyToken;

    @Override
    public Claims getClaimsFromToken(String jwtToken) {
        if (StringUtils.isNoneEmpty(jwtToken)) {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKeyToken.getBytes())
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
        }
        throw new MalformedJwtException("Invalid Token");
    }

}
