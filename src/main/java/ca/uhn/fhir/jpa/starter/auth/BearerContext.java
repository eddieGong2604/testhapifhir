
package ca.uhn.fhir.jpa.starter.auth;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class BearerContext implements Serializable {

    private static final long serialVersionUID = 1L;
    private String roleName;
    private String userId;
    private String bearerToken;

}
