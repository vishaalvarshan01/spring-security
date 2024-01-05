package com.spring.security.filters;

import com.spring.security.services.UserService;
import com.spring.security.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(StringUtils.isEmpty(authHeader) || !StringUtils.startsWithIgnoreCase(authHeader,"Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7);
        log.debug("JWT - {}",jwt);
        userEmail = jwtService.extractUserName(jwt);
         if(!userEmail.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
             UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);
             if(jwtService.isTokenValid(jwt,userDetails)){
                 log.debug("User - {}",userDetails);
                 SecurityContext context = SecurityContextHolder.createEmptyContext();
                 UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                 authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                 context.setAuthentication(authToken);
                 SecurityContextHolder.setContext(context);

             }
         }

         filterChain.doFilter(request,response);
    }
}
