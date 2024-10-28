package com.example.fakeshopapi.security.jwt.exception;

import lombok.Getter;

public enum JwtExceptionCode {
	
	BAD_CREDENTIALS("BAD_CREDENTIALS", "잘못된 자격 증명, Headers에 토큰 형식의 값 찾을 수 없음"),   //잘못된 자격 증명인 경우 (null이거나 사용자 예외사용할때 구분)
//	NOT_FOUND_TOKEN("NOT_FOUND_TOKEN", "Headers에 토큰 형식의 값 찾을 수 없음"), 	//찾을 수 없는 토큰인 경우
	INVALID_TOKEN("INVALID_TOKEN", "유효하지 않은 토큰"),						//잘못된 토큰인 경우
    EXPIRED_TOKEN("EXPIRED_TOKEN", "기간이 만료된 토큰"),		//*토큰이 만료된 경우 (JWT 토큰의 유효 기간이 지났을 때 발생)
    TOKEN_EXPIRED("TOKEN_EXPIRED", "만료된 토큰"),  		//*만료된 토큰인 경우(사용자가 만료된 토큰으로 요청을 시도했을 때 발생)
    UNSUPPORTED_TOKEN("UNSUPPORTED_TOKEN", "지원하지 않는 토큰"),				//지원되지 않는 토큰인 경우
	UNKNOWN_ERROR("UNKNOWN_ERROR", "UNKNOWN_ERROR"); 					//알 수 없는 오류인 경우
	
	

    @Getter
    private String code;

    @Getter
    private String message;

    JwtExceptionCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

}

/*토큰 관련 예외를 사용자 정의 예외로 보기 쉽게 만들고 싶다면, Java의 내장 예외와 겹치더라도 JwtExceptionCode와 같은 사용자 정의 예외 코드를 만듬
겹치는 항목:
BAD_CREDENTIALS (BadCredentialsException)
EXPIRED_TOKEN (ExpiredJwtException)
INVALID_TOKEN (MalformedJwtException, SignatureException)
UNSUPPORTED_TOKEN (UnsupportedJwtException)

*/

/* serialVersionUID는 자바 직렬화에서 사용, 객체를 역직렬화할 때 송신자와 수신자가 동일한 클래스를 로드했는지 확인하는 데 사용.
 * 만약 일치하지 않는다면 InvalidClassException이 발생
long value1 = 1;   // int 타입, 자동 형변환
long value2 = 1L;  // long 타입, 명시적 지정
long value3 = 10000000000; // 컴파일 오류 (int 범위 초과)
long value4 = 10000000000L; // 정상
*/