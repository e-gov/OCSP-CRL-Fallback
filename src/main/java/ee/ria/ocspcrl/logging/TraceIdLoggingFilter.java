package ee.ria.ocspcrl.logging;

import co.elastic.apm.api.ElasticApm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Deprecated // Move to eID-Common library
@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // Ensure that logging attributes are set as early as
                                   // possible.
public class TraceIdLoggingFilter extends OncePerRequestFilter {

    private static final String MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID = "trace.id";

    public static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestTraceId = ElasticApm.currentTransaction().getTraceId();
        boolean elasticApmTraceIdExists = StringUtils.isNotEmpty(requestTraceId);
        if (!elasticApmTraceIdExists) {
            // Use same format as Elastic APM Agent.
            requestTraceId = RandomStringUtils.random(32, "0123456789abcdef");
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for
        // Tomcat's AccessLogValve. Also used as incident number in ErrorAttributes.
        // Tracing ID-s from MDC cannot be used because Elastic APM agent adds tracing
        // ID-s to MDC right before the logging event is created and removes it right
        // after the event is logged. At other times, tracing ID-s are missing from MDC,
        // when Elastic APM agent is enabled.
        request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestTraceId);

        if (!elasticApmTraceIdExists) {
            MDC.put(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID, requestTraceId);
        }
        try {
            filterChain.doFilter(request, response);
        }
        finally {
            if (!elasticApmTraceIdExists) {
                MDC.remove(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID);
            }
        }
    }

}
