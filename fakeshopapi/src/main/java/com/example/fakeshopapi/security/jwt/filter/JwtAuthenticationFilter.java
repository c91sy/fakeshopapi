package com.example.fakeshopapi.security.jwt.filter;

import com.example.fakeshopapi.domain.RefreshToken;
import com.example.fakeshopapi.dto.AuthLoginDto;
import com.example.fakeshopapi.dto.AuthLoginResponseDto;
import com.example.fakeshopapi.dto.RefreshTokenDto;
import com.example.fakeshopapi.excption.SomeOtherException;
import com.example.fakeshopapi.security.jwt.exception.JwtExceptionCode;
import com.example.fakeshopapi.security.jwt.token.JwtAuthenticationToken;
import com.example.fakeshopapi.service.AuthService;
import com.example.fakeshopapi.service.RefreshTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
//import jakarta.servlet.*;
//import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
/** 요청을 필터링하고 인증을 처리하는 데 집중*/
	private final AuthenticationManager authenticationManager; //Spring Security 패키지에 포함된 AuthenticationManager 인터페이스 (인증처리, 예외처리)
    private final AuthService authService; // AuthService 인스턴스
    private final RefreshTokenService refreshTokenService; // RefeshService 인스턴스
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
    	
    	 /** 로그인 요청인지 확인*/
        boolean isLoginRequest = request.getRequestURI().equals("/auths/login");
        
        try {
        /* # 로그인 요청일 경우, 토큰 체크를 하지 않음 */
        	if (isLoginRequest) {
// 클라이언트가 보낸 JSON 형식의 로그인 정보를 Java 객체로 변환하여 처리하기 위해 ObjectMapper를 사용 로그인 DTO 추출하는 메서드 호출
                AuthLoginDto loginDto = new ObjectMapper().readValue(request.getInputStream(), AuthLoginDto.class); // 요청에서 DTO 추출
                AuthLoginResponseDto responseDto = authService.login(loginDto); // AuthService에서 리프레시토큰생성 로그인 처리

                // 응답 설정
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write(new ObjectMapper().writeValueAsString(responseDto)); // JSON 응답 반환
                return; // 메서드 종료
            }
        	
        	String token = getToken(request); // 로그인 요청이 아닐 경우, 토큰 가져오기(보안강화 설정)
        		//비로그인 요청(자동로그인)에서는 반드시 유효한 토큰이 필요하므로, 토큰을 가져와서 인증을 진행
        	if (token == null) {
                log.error("토큰이 존재하지 않거나 헤더에 잘못된 형식입니다.");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "토큰이 존재하지 않거나 유효하지 않습니다.");
                return;
            }
         /** 자동로그인시 만료된 토큰 처리: 리프레시 토큰이 유효한지 확인*/	
        /* # 비로그인 상태에서 Authorization 헤더 체크 */
        try {
        		Authentication authentication = getAuthentication(token);
        		SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response); // 필터 체인 실행 추가
        } catch (ExpiredJwtException expiredException) {
            log.info("토큰이 만료되었습니다. 리프레시 토큰을 확인 중입니다.");

            String refreshToken = request.getHeader("Refresh-Token"); // Refresh-Token 헤더에서 리프레시 토큰 가져오기
            log.debug("리프레시 토큰: {}", refreshToken);
            
            // RefreshTokenService를 사용하여 리프레시 토큰 조회
            Optional<RefreshToken> optionalRefreshToken = refreshTokenService.findRefreshToken(refreshToken);
            if (optionalRefreshToken.isPresent() && authService.validateRefreshToken(refreshToken)) {
                AuthLoginResponseDto newTokens = authService.refreshAccessToken(new RefreshTokenDto(refreshToken));
                response.setHeader("Authorization", "Bearer " + newTokens.getAccessToken()); // 리프레시 토큰이 유효하다면 새로운 액세스 토큰 발급
                log.info("새로운 액세스 토큰을 발급했습니다.");
                filterChain.doFilter(request, response);
            }else{
// 이 코드는 보안을 강화하는 데 중요한 역할을 합니다. 로그인 요청을 제외한 모든 요청에서는 유효한 JWT 토큰이 필수임을 명시적으로 확인하는 것
            	 response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "리프레시 토큰이 유효하지 않습니다.");
            }     
        } catch (BadCredentialsException e) { // 새로운 예외 처리 추가
            request.setAttribute("exception", JwtExceptionCode.BAD_CREDENTIALS.getCode());
            //log.error("Bad Credentials // token : {}", token); //token 변수의 값을 로그에 출력 보안상 안하는게 좋음
            log.error("Set Request Exception Code : {}", request.getAttribute("exception")); //request 객체의 "exception" 속성에 저장된 값을 출력하는 기능, 주로 예외 상황에서 추가 정보를 기록하기 위해 사용
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 401에러 응답 전송
            return; // 메서드 종료    
        } catch (NullPointerException e) {
            request.setAttribute("exception", JwtExceptionCode.BAD_CREDENTIALS.getCode());
            log.error("Headers에 토큰 형식의 값 찾을 수 없음");
            //log.error("Not Found Token // message: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (SecurityException | MalformedJwtException e) {
            request.setAttribute("exception", JwtExceptionCode.INVALID_TOKEN.getCode());
            log.error("Invalid Token // SecurityException occurred"); //JWT 토큰의 유효 기간이 지나 만료된 토큰
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (SomeOtherException e) {
            request.setAttribute("exception", JwtExceptionCode.TOKEN_EXPIRED.getCode());
            log.error("Token expired while using"); // 사용자가 만료된 토큰 사용 시 처리 (예: 특정 예외 클래스)
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (UnsupportedJwtException e) {
            request.setAttribute("exception", JwtExceptionCode.UNSUPPORTED_TOKEN.getCode());
            log.error("Unsupported Token"); //지원되지 않는 토큰
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        }
        } catch (Exception e) {
        	request.setAttribute("exception", JwtExceptionCode.UNKNOWN_ERROR.getCode()); // 나머지예외
            log.error("====================================================");
            log.error("JwtFilter - doFilterInternal() 오류 발생");
            log.error("Exception Message : {}", e.getMessage());
            log.error("Exception StackTrace : {");
            e.printStackTrace();
            log.error("}");
            log.error("====================================================");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        }
    }
// JWT 토큰을 인증하는 메서드 (인증된 정보를 SecurityContextHolder에 설정)
    private Authentication getAuthentication(String token) {
    	JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(token);
        return authenticationManager.authenticate(authenticationToken); // 인증을 수행하고 인증 객체 반환
    } 	//이 메서드는 Authentication 객체를 반환합니다.
    	//호출하는 곳에서 이 객체를 사용하여 SecurityContextHolder에 설정하거나, 필요한 정보를 꺼내올 수 있습니다.

//이 메서드는 HttpServletRequest 객체를 매개변수로 받아, 직접적으로 요청의 헤더를 검사
    private String getToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        log.debug("Authorization Header: {}", authorization);
        if (authorization == null) {
        	return null; // 로그인 요청 시 null 반환, 예외 발생하지 않음
        }
// Authorization 헤더가 비어있거나 "Bearer "로 시작하지 않는 경우
        if (StringUtils.hasText(authorization) && authorization.startsWith("Bearer")){
        	return authorization.substring(7); // "Bearer " 뒤의 토큰 반환
        }
        throw new BadCredentialsException("잘못된 Authorization 헤더 형식입니다."); // 잘못된 형식의 경우 예외 발생
    }
}

/*
if (request.getRequestURI().equals("/members/logout"))
- 먼저 request.getRequestURI()의 값을 가져와서 이를 "/members/logout"과 비교
- 만약 request.getRequestURI()가 null인 경우, NullPointerException이 발생

if ("/members/logout".equals(request.getRequestURI()))
- "/members/logout" 문자열의 equals 메서드를 호출, request.getRequestURI()가 null이더라도 예외가 발생하지 않고 false를 반환
- 위에랑 달리 대소문자 구분을 하지않고 문자열을 먼저 평가를 해서 약간 더 빠름

*/