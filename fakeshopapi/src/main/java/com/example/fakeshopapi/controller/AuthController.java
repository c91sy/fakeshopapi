package com.example.fakeshopapi.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.fakeshopapi.domain.Member;
import com.example.fakeshopapi.domain.RefreshToken;

import com.example.fakeshopapi.dto.AuthLoginDto;
import com.example.fakeshopapi.dto.AuthLoginResponseDto;
import com.example.fakeshopapi.dto.RefreshTokenDto;
import com.example.fakeshopapi.security.jwt.exception.JwtExceptionCode;
import com.example.fakeshopapi.security.jwt.util.JwtTokenizer;
import com.example.fakeshopapi.service.AuthService;
import com.example.fakeshopapi.service.MemberService;
import com.example.fakeshopapi.service.RefreshTokenService;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auths") //(http://localhost:8081/auths/)
@Validated  				//전체 클래스 레벨에서 유효성 검사를 활성화
public class AuthController {
	private final JwtTokenizer jwtTokenizer;
	private final RefreshTokenService refreshTokenService;
    private final AuthService authService;
    private final MemberService memberService;
    private static final Logger log = LoggerFactory.getLogger(MemberController.class);
    						//ResponseEntity<MemberLoginResponseDto>: 로그인 성공 시 반환할 응답 데이터의 구조를 정의
    @PostMapping("/login")  //MemberLoginDto: 클라이언트가 보낸 로그인 요청 데이터의 유효성을 검사
    public ResponseEntity<AuthLoginResponseDto> login(@RequestBody @Valid AuthLoginDto loginDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST); //400에러
        } //ResponseEntity는 HTTP 응답을 나타내는 객체고 타입을 담아서 보내는거라 반환이라한다

        // 로그인 응답 객체 생성 및 반환 (로그인 성공 시 수행되는 코드)
        AuthLoginResponseDto loginResponse = authService.login(loginDto);

        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    } 	// 로그인 응답 객체를 생성하고 HTTP 200 OK 상태와 함께 반환
/**토큰이 없는 경우 (Null)와 사용자예외를 사용할 때는 BadCredentialsException을 계속 사용한다*/
    @DeleteMapping("/logout") //<String>을 사용하는 이유는 로그아웃 요청의 결과로 문자열 메시지를 반환하고자 하기 때문
    public ResponseEntity<String> logout(@RequestBody RefreshTokenDto refreshTokenDto, HttpServletRequest request) {
    	// 토큰이 존재하는지 확인
        String token = getToken(request);
        if (token == null) { //Spring Security에서 인증 과정에서 제공된 토큰이 잘못되었거나 유효하지 않을 때 발생하는 예외
        	log.warn("로그아웃 실패: 토큰이 존재하지 않습니다.");
        	request.setAttribute("exception", JwtExceptionCode.BAD_CREDENTIALS.getCode()); // 예외 속성 설정
        	throw new BadCredentialsException("토큰이 존재하지 않습니다."); // 전역 예외 처리기로 위임
          }
        // 만료된 토큰인 경우 (사용자가 요청을 시도했을 때 이미 만료된 토큰을 사용하려고 할 때
        if (jwtTokenizer.isTokenExpired(token, jwtTokenizer.getAccessSecret())) {
            log.warn("토큰이 만료되었습니다: {}", token); // 만료된 토큰이지만 로그아웃 진행
            request.setAttribute("exception", JwtExceptionCode.TOKEN_EXPIRED.getCode()); // 예외 속성 설정
            throw new BadCredentialsException("만료된 토큰입니다."); // 전역 예외 처리기로 위임
        }
   // Refresh Token 삭제 **AuthService의 logout 메서드 호출** (대부분의 경우, 로그아웃 시 액세스 토큰과 리프레시 토큰을 모두 삭제)
        authService.logout(refreshTokenDto.getRefreshToken()); //Service의 logout 메서드를 호출하고, 해당 리프레시 토큰을 삭제하는 작업을 수행
        SecurityContextHolder.clearContext(); // 인증 정보 지우기
        return ResponseEntity.ok().body("로그아웃 성공");
      } 
    private String getToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");// HTTP 요청의 Authorization 헤더에서 토큰 값을 가져옴
        if (StringUtils.hasText(authorization) && authorization.startsWith("Bearer ")) {
        	return authorization.substring(7); // "Bearer " 접두사를 제외한 JWT 토큰 값을 반환합니다.
        }
        return null; // 토큰을 찾지 못하는 경우 null을 반환
    }
  /**  getToken 메서드의 역할
    	로그인 이후의 인증:
    	getToken 메서드는 주로 사용자가 인증이 필요한 요청(예: 로그아웃, 보호된 리소스 접근 등)을 할 때 사용됩니다.
    	로그인 시에는 이 메서드가 호출되지 않으며, 로그인 후에 사용자가 인증된 상태로 요청을 보낼 때 사용됩니다.  */ 

//HTTP 200 OK: 로그아웃 요청이 성공적으로 처리되었음을 나타내며, 추가적인 응답 본문을 포함할 수 있습니다. 예를 들어, 로그아웃 후에 메시지를 포함할 수 있습니다.
/*	return new ResponseEntity(HttpStatus.NO_CONTENT);
HTTP 204 No Content: 로그아웃 요청이 성공적으로 처리되었지만, 반환할 콘텐츠가 없음을 나타냅니다.
클라이언트는 로그아웃이 성공했음을 알 수 있지만, 추가적인 데이터는 필요하지 않을 때 사용됩니다.	*/

    /*
    1. 전달받은 유저의 아이디로 유저가 존재하는지 확인한다.
    2. RefreshToken이 유효한지 체크한다.
    3. AccessToken을 발급하여 기존 RefreshToken과 함께 응답한다.
     */
    @PostMapping("/refreshToken") //MemberLoginResponseDto에 accessToken과 refreshToken이 포함되어 있어서 타입으로 반환
    public ResponseEntity<AuthLoginResponseDto> requestRefresh(@RequestBody RefreshTokenDto refreshTokenDto) {
        RefreshToken refreshToken = refreshTokenService.findRefreshToken(refreshTokenDto.getRefreshToken()).orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));
        Claims claims = jwtTokenizer.parseRefreshToken(refreshToken.getValue());
//Claims은 jwt로 전달된 payload에 포함된 내용 id, role 등 (첫줄은 db에서 정보를확인하고 Refresh Token의 유효성을 검사)
        Long memberId = Long.valueOf((Integer)claims.get("memberId"));

        Member member = memberService.getMember(memberId).orElseThrow(() -> new IllegalArgumentException("Member not found"));


        List<String> roles = (List<String>) claims.get("roles"); // 타입을 명확히 지정
        String email = claims.getSubject();
        // 새로운 액세스 토큰 생성
        String accessToken = jwtTokenizer.createAccessToken(memberId, email, member.getName(), roles);
        
        // 새로운 리프레시 토큰 생성
        String newRefreshToken = jwtTokenizer.createRefreshToken(memberId, email, member.getName(), roles);
        
        // 기존 리프레시 토큰 삭제 및 새로운 리프레시 토큰 저장
        refreshTokenService.deleteRefreshToken(refreshTokenDto.getRefreshToken());
        // 응답 객체 생성
        AuthLoginResponseDto loginResponse = AuthLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenDto.getRefreshToken())
                .memberId(member.getMemberId())
                .nickname(member.getName())
                .build();
        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    }
}
