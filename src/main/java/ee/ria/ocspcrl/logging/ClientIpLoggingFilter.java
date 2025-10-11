package ee.ria.ocspcrl.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
public class ClientIpLoggingFilter extends OncePerRequestFilter {

    private static final String MDC_ATTRIBUTE_KEY_CLIENT_IP = "client.ip";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String ipAddress = request.getRemoteAddr();
        boolean ipAddressExists = StringUtils.isNotEmpty(ipAddress);

        if (ipAddressExists) {
            MDC.put(MDC_ATTRIBUTE_KEY_CLIENT_IP, ipAddress);
        }
        try {
            filterChain.doFilter(request, response);
        }
        finally {
            if (ipAddressExists) {
                MDC.remove(MDC_ATTRIBUTE_KEY_CLIENT_IP);
            }
        }
    }

}
