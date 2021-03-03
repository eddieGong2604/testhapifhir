package ca.uhn.fhir.jpa.starter.interceptor;

import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.jpa.starter.auth.BearerContext;
import ca.uhn.fhir.jpa.starter.auth.BearerContextHolder;
import ca.uhn.fhir.jpa.starter.token.TokenInterpreter;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.apache.commons.lang3.StringUtils;
import org.hl7.fhir.dstu2.model.IdType;
import org.hl7.fhir.dstu2.model.Patient;
import org.hl7.fhir.dstu2.model.Practitioner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Interceptor
@Component
public class PatientAndAdminAuthorizationInterceptor extends AuthorizationInterceptor {
	public static final String INVALID_TOKEN_MESSAGE = "Invalid token";
	public static final String INVALID_TOKEN_PARAM = "Invalid %s";
	public static final String USER_NAME_CLAIM_NAME = "user_name";
	public static final String USER_ID_CLAIM_NAME = "user_id";
	public static final String ROLE_CLAIM_NAME = "role";
	public static final String CLIENT_ID_CLAIM_NAME = "client_id";
	private final TokenInterpreter tokenProvider;

	public PatientAndAdminAuthorizationInterceptor(TokenInterpreter tokenProvider) {
		this.tokenProvider = tokenProvider;
	}

	@Override
	public void incomingRequestPreHandled(RequestDetails theRequest, Pointcut thePointcut) {
		try {
			if (containsToken(theRequest)) {
				Claims claims = validateToken(theRequest);
				Optional<String> userId = Optional.ofNullable((String) claims.get(USER_ID_CLAIM_NAME));
				Optional<String> roleName = Optional.ofNullable((String) claims.get(ROLE_CLAIM_NAME));
				BearerContext context = BearerContextHolder.getContext();
				context.setUserId(userId.orElseThrow(() ->
					new AuthenticationException(String.format(INVALID_TOKEN_PARAM, USER_ID_CLAIM_NAME))));
				context.setRoleName(roleName.orElseThrow(() ->
					new AuthenticationException(String.format(INVALID_TOKEN_PARAM, ROLE_CLAIM_NAME))));
			} else {
				BearerContext context = BearerContextHolder.getContext();
				context.setRoleName("USER");
			}
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException e) {
			throw new AuthenticationException(e.getMessage());
		}
	}

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		IdType userIdPatientId = null;
		IdType userIdPractitionerId = null;
		if (BearerContextHolder.getContext().getRoleName().equalsIgnoreCase("PATIENT")) {
			userIdPatientId = new IdType("Patient", BearerContextHolder.getContext().getUserId());
		} else if (BearerContextHolder.getContext().getRoleName().equalsIgnoreCase("PRACTITIONER")) {
			userIdPractitionerId = new IdType("Practitioner", BearerContextHolder.getContext().getUserId());
		} else if (BearerContextHolder.getContext().getRoleName().equalsIgnoreCase("ADMIN")) {
			return new RuleBuilder()
				.allowAll()
				.build();
		} else if (BearerContextHolder.getContext().getRoleName().equalsIgnoreCase("USER")) {
			return new RuleBuilder().allow("Allow external user to create Patient").create().resourcesOfType(Patient.class).withAnyId().andThen().allow("Allow external user to create Practitioner").create().resourcesOfType(Practitioner.class).withAnyId().andThen().denyAll("Not allow external user to access unauthorized resources").build();
		} else {
			throw new AuthenticationException("Missing or invalid Authorization header value");
		}
		if (userIdPatientId != null) {
			return new RuleBuilder()
				.allow().read().allResources().inCompartment("Patient", userIdPatientId).andThen()
				.allow().write().allResources().inCompartment("Patient", userIdPatientId).andThen()
				.denyAll("Can not read/write to unauthorized resources")
				.build();
		} else {
			return new RuleBuilder()
				.allow().read().allResources().inCompartment("Practitioner", userIdPractitionerId).andThen()
				.allow().write().allResources().inCompartment("Practitioner", userIdPractitionerId).andThen()
				.denyAll("Can not read/write to unauthorized resources")
				.build();
		}

	}

	private boolean containsToken(RequestDetails request) {
		String authenticationHeader = request.getHeader("Authorization");
		return authenticationHeader != null && authenticationHeader.startsWith("Bearer");
	}

	private Claims validateToken(RequestDetails request) {
		String jwtToken = request.getHeader("Authorization").replace("Bearer",
			StringUtils.EMPTY);
		BearerContextHolder.getContext().setBearerToken(jwtToken);
		return tokenProvider.getClaimsFromToken(jwtToken);
	}

}