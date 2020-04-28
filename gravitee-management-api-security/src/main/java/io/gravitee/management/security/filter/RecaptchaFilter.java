package io.gravitee.management.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.management.service.ReCaptchaService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RecaptchaFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(RecaptchaFilter.class);

    private ReCaptchaService reCaptchaService;

    private ObjectMapper objectMapper;

    public RecaptchaFilter(ReCaptchaService reCaptchaService, ObjectMapper objectMapper) {
        this.reCaptchaService = reCaptchaService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if(httpRequest.getPathInfo().equals("/users/registration")) {

            LOGGER.info("Checking captcha");

            String reCaptchaToken = httpRequest.getHeader("ReCaptchaToken");

            if(!reCaptchaService.isValid(reCaptchaToken)) {

                HashMap<String, Object> error = new HashMap<>();

                error.put("message", "An error occured");
                error.put("http_status", SC_UNAUTHORIZED);

                httpResponse.setStatus(SC_UNAUTHORIZED);
                httpResponse.setContentType(MediaType.APPLICATION_JSON.toString());
                httpResponse.getWriter().write(objectMapper.writeValueAsString(error));
                httpResponse.getWriter().close();
            }else {
                chain.doFilter(request, response);
            }
        } else {
            chain.doFilter(request, response);
        }
    }
}