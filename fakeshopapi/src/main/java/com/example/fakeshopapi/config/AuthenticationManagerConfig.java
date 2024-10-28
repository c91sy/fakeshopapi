package com.example.fakeshopapi.config;


import com.example.fakeshopapi.security.jwt.filter.JwtAuthenticationFilter;
import com.example.fakeshopapi.security.jwt.provider.JwtAuthenticationProvider;
import com.example.fakeshopapi.service.AuthService;
import com.example.fakeshopapi.service.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class AuthenticationManagerConfig extends AbstractHttpConfigurer<AuthenticationManagerConfig, HttpSecurity> {

    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final AuthService authService; //추가 (기존 필터는 AuthService를 인자로 받고 있는데, AuthenticationManager를 인자로 받도록 변경해야함)
    private final RefreshTokenService refreshTokenService;
    
    @Override
    public void configure(HttpSecurity builder) throws Exception {
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        // 인증을 위한 필터 추가
        builder.addFilterBefore(
                new JwtAuthenticationFilter(authenticationManager, authService, refreshTokenService),
                UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(jwtAuthenticationProvider);
        // 여기에 접근 권한 설정 추가
        builder.authorizeRequests()
               .antMatchers("/auths/login").permitAll()  // 로그인 경로는 인증 필요 없음
               .anyRequest().authenticated();  // 그 외 모든 요청은 인증 필요
    }
}

/*
 이 클래스는 JWT 기반 인증을 위한 Spring Security 설정을 정의하고 있으며, JwtAuthenticationFilter를 사용하여 JWT 토큰을 검증하고
 JwtAuthenticationProvider를 통해 인증을 처리하도록 구성
 */
