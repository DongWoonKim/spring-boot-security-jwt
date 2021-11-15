package com.example.springbootsecurityjwt.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }


    // 실제 필터링
    // 토큰의 인증정보를 SecurityContext에 저장하는 역할
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String jwt = resolveToken(httpServletRequest);
        String reqURI = httpServletRequest.getRequestURI();


        if(StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) { // 토큰 유효성 검사
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("SecurityContext에 인증 정보를 저장했습니다. uri : {}", authentication.getName(), reqURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다. uri : {}", reqURI);
        }

        chain.doFilter(request, response);
    }

    // Request Header에서 토큰 정보를 꺼내오는 역할
    private String resolveToken(HttpServletRequest req) {
        String token = req.getHeader(AUTHORIZATION_HEADER);
        if(StringUtils.hasText(token) && token.startsWith("Bearer")) {
            return token.substring(7);
        }
        return null;
    }

}
