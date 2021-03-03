
package ca.uhn.fhir.jpa.starter.auth;

public abstract class BearerContextHolder {

	private BearerContextHolder() {
		// Private constructor
	}

	private static final ThreadLocal<BearerContext> contextHolder = new ThreadLocal<>();

	/**
	 *
	 */
	public static void clearContext() {
		contextHolder.remove();
	}

	/**
	 *
	 * @return
	 */
	public static BearerContext getContext() {
		BearerContext ctx = contextHolder.get();
		if (ctx == null) {
			ctx = createEmptyContext();
			contextHolder.set(ctx);
		}
		return ctx;
	}

	/**
	 *
	 * @param context
	 */
	public static void setContext(BearerContext context) {
		if (context != null) {
			contextHolder.set(context);
		}
	}

	/**
	 *
	 * @return
	 */
	public static BearerContext createEmptyContext() {
		return new BearerContext();
	}
}
