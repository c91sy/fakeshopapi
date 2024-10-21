package com.example.fakeshopapi.security.jwt.filter;


import com.example.fakeshopapi.excption.SomeOtherException;
import com.example.fakeshopapi.security.jwt.exception.JwtExceptionCode;
import com.example.fakeshopapi.security.jwt.token.JwtAuthenticationToken;
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

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
/** 요청을 필터링하고 인증을 처리하는 데 집중*/
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
    	
    	 /** 로그인 요청인지 확인*/
        boolean isLoginRequest = request.getRequestURI().equals("/auths/login");
        String token = null; // 토큰 변수를 초기화
        try {
        /* # 로그인 요청일 경우, 토큰 체크를 하지 않음 */
        	if (isLoginRequest) {
                filterChain.doFilter(request, response); // 필터 체인 실행
                return; // 메서드 종료
            }
        	
        	token = getToken(request); // 로그인 요청이 아닐 경우, 토큰 가져오기(보안강화 설정)
        		//비로그인 요청(자동로그인)에서는 반드시 유효한 토큰이 필요하므로, 토큰을 가져와서 인증을 진행
        	
        /* # 비로그인 상태에서 Authorization 헤더 체크 */
            if (StringUtils.hasText(token)) {
                getAuthentication(token); // 토큰이 있는 경우 인증 처리
            }else{
// 이 코드는 보안을 강화하는 데 중요한 역할을 합니다. 로그인 요청을 제외한 모든 요청에서는 유효한 JWT 토큰이 필수임을 명시적으로 확인하는 것
                throw new BadCredentialsException("토큰이 존재하지 않거나 유효하지 않습니다."); // 로그인 요청이 아닌 경우에만 토큰이 없을 때 예외 발생
            }
            filterChain.doFilter(request, response); // 필터 체인 실행 추가
        } catch (BadCredentialsException e) { // 새로운 예외 처리 추가
            request.setAttribute("exception", JwtExceptionCode.BAD_CREDENTIALS.getCode());
            log.error("Bad Credentials // token : {}", token);
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 401에러 응답 전송
            return; // 메서드 종료    
        } catch (NullPointerException | IllegalStateException e) {
            request.setAttribute("exception", JwtExceptionCode.NOT_FOUND_TOKEN.getCode());
            log.error("Not found Token // token : {}", token);
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (SecurityException | MalformedJwtException e) {
            request.setAttribute("exception", JwtExceptionCode.INVALID_TOKEN.getCode());
            log.error("Invalid Token // token : {}", token);
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (ExpiredJwtException e) {
            request.setAttribute("exception", JwtExceptionCode.EXPIRED_TOKEN.getCode());
            log.error("EXPIRED Token // token : {}", token);
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (SomeOtherException e) { // 만료된 토큰 사용 시 처리 (예: 특정 예외 클래스)
            request.setAttribute("exception", JwtExceptionCode.TOKEN_EXPIRED.getCode());
            log.error("Token expired while using // token : {}", token);
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (UnsupportedJwtException e) {
            request.setAttribute("exception", JwtExceptionCode.UNSUPPORTED_TOKEN.getCode());
            log.error("Unsupported Token // token : {}", token);
            log.error("Set Request Exception Code : {}", request.getAttribute("exception"));
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        } catch (Exception e) {
        	request.setAttribute("exception", JwtExceptionCode.UNKNOWN_ERROR.getCode()); // 나머지예외
            log.error("====================================================");
            log.error("JwtFilter - doFilterInternal() 오류 발생");
            log.error("token : {}", token);
            log.error("Exception Message : {}", e.getMessage());
            log.error("Exception StackTrace : {");
            e.printStackTrace();
            log.error("}");
            log.error("====================================================");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"); // 응답 전송
            return; // 메서드 종료
        }
    }

    private void getAuthentication(String token) {
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(token);
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
                // 이 객체에는 JWT안의 내용을 가지고 로그인 id(email),role
        SecurityContextHolder.getContext().setAuthentication(authenticate); // 현재 요청에서 언제든지 인증정보를 꺼낼 수 있도록 해준다.
    } //SecurityContextHolder에다가 만들어진 Authentication를 담아둠

//이 메서드는 HttpServletRequest 객체를 매개변수로 받아, 직접적으로 요청의 헤더를 검사
    private String getToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        log.debug("Authorization Header: {}", authorization);
        if (authorization == null) {
        	return null; // 로그인 요청 시 null 반환, 예외 발생하지 않음
        }
        
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