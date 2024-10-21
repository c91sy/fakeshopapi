package com.example.fakeshopapi.security.jwt.exception;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

@Slf4j
@Component // Spring의 컴포넌트로 등록하여 의존성 주입이 가능
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
/** 요청을 필터링하고 인증을 처리하는 데 집중*/// 인증 실패 시 호출되는 메서드 (로그인과 로그아웃 모두에 사용) 다양한 인증 관련 예외를 처리
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String exception = (String) request.getAttribute("exception");
        log.error("Commence Get Exception : {}", exception); // 로그에 예외 정보를 기록합니다.
/* 예외가 null인 경우, 즉 첫 로그인 시 처리 */
        if(exception == null) {
        	log.info("첫 로그인 - 토큰 없음. 로그인 허용.");
            log.error("entry point >> exception is null");// null 예외 로그 기록(첫 로그인 시에는 아직 발급된 토큰이 없으므로 로그에서 예외로 기록)
            return; //여기서는 아무런 오류 응답을 보내지 않고 메서드 종료
//            setResponse(response, JwtExceptionCode.NOT_FOUND_TOKEN); // 토큰이 없다는 응답을 설정합니다.
        }
/*예외 코드에 따라 적절한 처리 수행*/
        //잘못된 자격 증명인 경우 (null이거나 사용자 예외사용할때 구분)
        if (exception.equals(JwtExceptionCode.BAD_CREDENTIALS.getCode())) {
            log.error("entry point >> bad credentials");
            setResponse(response, JwtExceptionCode.BAD_CREDENTIALS); // 적절한 오류 코드 설정
        }
        //찾을 수 없는 토큰인 경우
        else if (exception.equals(JwtExceptionCode.NOT_FOUND_TOKEN.getCode())) {
            log.error("entry point >> not found token");
            setResponse(response, JwtExceptionCode.NOT_FOUND_TOKEN);
        }
        //잘못된 토큰인 경우
        else if(exception.equals(JwtExceptionCode.INVALID_TOKEN.getCode())) {
            log.error("entry point >> invalid token");
            setResponse(response, JwtExceptionCode.INVALID_TOKEN);
        }
        //*토큰 만료된 경우 (JWT 토큰의 유효 기간이 지났을 때 발생, 사용자가 요청을 시도했을 때 이미 만료된 토큰을 사용하려고 할 때)
        else if(exception.equals(JwtExceptionCode.EXPIRED_TOKEN.getCode())) {
            log.error("entry point >> expired token");
            setResponse(response, JwtExceptionCode.EXPIRED_TOKEN);
        }
        //*만료된 토큰인 경우(사용자가 요청을 시도했을 때 이미 만료된 토큰을 사용하려고 할 때)
        else if (exception.equals(JwtExceptionCode.TOKEN_EXPIRED.getCode())) {
            log.error("entry point >> token expired");
            setResponse(response, JwtExceptionCode.TOKEN_EXPIRED);
        }
        //지원되지 않는 토큰인 경우
        else if(exception.equals(JwtExceptionCode.UNSUPPORTED_TOKEN.getCode())) {
            log.error("entry point >> unsupported token");
            setResponse(response, JwtExceptionCode.UNSUPPORTED_TOKEN);
        }
        //알 수 없는 오류인 경우
        else {
        	log.error("entry point >> unknown error");
            setResponse(response, JwtExceptionCode.UNKNOWN_ERROR); 
        }
    }

    private void setResponse(HttpServletResponse response, JwtExceptionCode exceptionCode) throws IOException {
        response.setContentType("application/json;charset=UTF-8"); // 응답의 콘텐츠 타입을 JSON으로 설정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);  // HTTP 상태 코드를 401로 설정 (인증 실패)

        HashMap<String, Object> errorInfo = new HashMap<>();  // 오류 정보를 담을 해시맵 생성
        errorInfo.put("message", exceptionCode.getMessage()); // 오류 메시지 추가
        errorInfo.put("code", exceptionCode.getCode()); // 오류 코드 추가
        Gson gson = new Gson(); // Gson 객체 생성 (HashMap<String, Object> 형태로 저장된 오류정보를 JSON 문자열로 변환하고 이를 클라이언트에게 응답으로 보내기 위해)
        String responseJson = gson.toJson(errorInfo); // 해시맵을 JSON 문자열로 변환
        response.getWriter().print(responseJson); // JSON 응답을 클라이언트에 출력
    }
}
