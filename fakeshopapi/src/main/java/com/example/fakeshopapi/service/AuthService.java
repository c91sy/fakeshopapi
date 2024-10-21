package com.example.fakeshopapi.service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.fakeshopapi.domain.Member;
import com.example.fakeshopapi.domain.RefreshToken;
import com.example.fakeshopapi.domain.Role;
import com.example.fakeshopapi.dto.AuthLoginDto;
import com.example.fakeshopapi.dto.AuthLoginResponseDto;
import com.example.fakeshopapi.dto.RefreshTokenDto;
import com.example.fakeshopapi.excption.UserNotFoundException;
import com.example.fakeshopapi.security.jwt.util.JwtTokenizer;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final MemberService memberService; // MemberService 주입
	private final PasswordEncoder passwordEncoder;
	private final JwtTokenizer jwtTokenizer; // JWT 토큰 관련 유틸리티
	private final RefreshTokenService refreshTokenService; // 리프레시 토큰 관리
	private static final Logger log = LoggerFactory.getLogger(AuthService.class);
	
/** 이메일을 입력하여 로그인하려고 할 때, 해당 이메일을 기반으로 데이터베이스에서 사용자의 정보를 조회 */
	public AuthLoginResponseDto login(AuthLoginDto loginDto) {
		log.debug("로그인 요청 수신: {}", loginDto.getEmail()); // 요청 수신 로그
	   Member member = memberService.findByEmail(loginDto.getEmail());
	 //email이 없을 경우 Exception이 발생한다. Global Exception에 대한 처리가 필요하다. (비밀번호는 아래 로직 구현으로 충분) (일반적인 try-catch 블록을 사용하는 것보다 보안상 더 안전)
       if (member == null) {
    	   log.error("사용자 없음: {}", loginDto.getEmail());
    	   
           throw new UserNotFoundException("User not found with email: " + loginDto.getEmail());
       } //특정 유형의 오류를 명확히 식별, ResponseEntity를 사용하여 HTTP 응답을 직접 생성하는 대신, 예외를 던져 전역 예외 처리기로 위임
       // 일반적인 리턴 대신 throw new를 사용하여 예외를 발생시키는 것이 더 적절(RESTful API 개발 시 유용)
       
//이메일은 문자열(String)이므로 == 연산자를 사용하여 null 체크를 하지만 비밀번호 검증에서는 객체의 password 필드를 직접 비교해야함
       // 비밀번호가 비어 있는지 체크
       if (loginDto.getPassword() == null || loginDto.getPassword().isEmpty()) {
    	   log.error("비밀번호가 비어 있습니다.");
    	   throw  new IllegalArgumentException("비밀번호가 비어 있습니다.");
       }
       
       // 비밀번호 검증(확인)				암호화가 안된 암호(로그인시도)		DB에 있는 암호
       if(!passwordEncoder.matches(loginDto.getPassword(), member.getPassword())){
    	   log.error("비밀번호가 틀립니다: {}", loginDto.getEmail());
    	   throw new BadCredentialsException("비밀번호가 틀림니다."); // 잘못된 비밀번호 예외
       }
       
       // List<Role> ===> List<String> 역할 리스트 변환  	Role::getName은 메서드 참조
       List<String> roles = member.getRoles().stream().map(Role::getName).collect(Collectors.toList());

       // JWT토큰을 생성하였다. jwt라이브러리를 이용하여 액세스, 리프레시  토큰생성. (jwtTokenizer)
       String accessToken = jwtTokenizer.createAccessToken(member.getMemberId(), member.getEmail(), member.getName(), roles);
       String refreshToken; // = jwtTokenizer.createRefreshToken(member.getMemberId(), member.getEmail(), member.getName(), roles);
       
    // 기존 리프레시 토큰이 있는지 확인
       Optional<RefreshToken> existingRefreshToken = refreshTokenService.findRefreshTokenByMemberId(member.getMemberId());
       if (existingRefreshToken.isPresent()) {
           // 기존 리프레시 토큰이 있으면 사용
           refreshToken = existingRefreshToken.get().getValue();
       } else{
       refreshToken = jwtTokenizer.createRefreshToken(member.getMemberId(), member.getEmail(), member.getName(), roles);
//아이디암호가 맞으면 새로운 RefreshToken을 DB에 저장한다. 성능 때문에 일반적으로 DB가 아니라 Redis에(인메모리 데이터베이스) 저장하는 것이 좋다.
       RefreshToken refreshTokenEntity = new RefreshToken();
       refreshTokenEntity.setValue(refreshToken);
       refreshTokenEntity.setMemberId(member.getMemberId());
       refreshTokenService.addRefreshToken(refreshTokenEntity); // DB에 리프레시 토큰 저장
       }
       // 디버깅 로그 추가
       log.debug("발급된 Access Token: {}", accessToken); // Access Token 로그
       log.debug("발급된 Refresh Token: {}", refreshToken); // Refresh Token 로그
       // 로그인 응답 객체 생성 및 반환 (로그인 성공 시 수행되는 코드)
       return AuthLoginResponseDto.builder() // AuthLoginResponseDto를 반환
               .accessToken(accessToken)
               .refreshToken(refreshToken)
               .memberId(member.getMemberId())
               .nickname(member.getName())
               .build();
	}
	
	/**
     * Access Token 연장
     */
    public AuthLoginResponseDto refreshAccessToken(RefreshTokenDto refreshTokenDto) {
        String refreshToken = refreshTokenDto.getRefreshToken();
        // Optional<RefreshToken>으로 반환
        RefreshToken storedRefreshToken = refreshTokenService.findRefreshToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다."));

        Claims claims = jwtTokenizer.parseRefreshToken(refreshToken);
        Long memberId = claims.get("memberId", Long.class);
        String email = claims.getSubject();
        String name = claims.get("name", String.class);
        List<String> roles = claims.get("roles", List.class);

        String newAccessToken = jwtTokenizer.createAccessToken(memberId, email, name, roles);

        return AuthLoginResponseDto.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken) // 기존 리프레시 토큰을 반환
                .memberId(memberId)
                .nickname(name)
                .build();
    }
/** 로그아웃 */
	public void logout(String refreshToken) {
        // 리프레시 토큰 삭제
        refreshTokenService.deleteRefreshToken(refreshToken);
        // 여기서 추가적인 비즈니스 로직이 필요할 경우 구현
    }

    /**
     * RefreshTokenRotation
     */
	public String rotateRefreshToken(String oldRefreshToken) {
        Optional<RefreshToken> storedRefreshToken = refreshTokenService.findRefreshToken(oldRefreshToken);
        
        if (storedRefreshToken.isEmpty()) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // Refresh Token에서 정보 추출
        Long memberId = storedRefreshToken.get().getMemberId();
//리프레시 토큰 테이블: member_id를 통해 사용자를 식별하고 리프레시 토큰을 관리. 회원 테이블: 이메일을 통해 사용자를 조회하고 인증.
        Optional<Member> memberOpt = memberService.getMember(memberId); // memberOpt 정의

        // Optional<Member>의 존재 여부를 체크
        if (memberOpt.isPresent()) {
            Member member = memberOpt.get(); // memberOpt에서 Member 객체를 가져옴
            List<String> roles = member.getRoles().stream().map(Role::getName).collect(Collectors.toList());

            // 새로운 Refresh Token 생성
            String newRefreshToken = jwtTokenizer.createRefreshToken(memberId, member.getEmail(), member.getName(), roles);

            // 기존 Refresh Token 무효화
            refreshTokenService.deleteRefreshToken(oldRefreshToken);

            // 새로운 Refresh Token 저장
            RefreshToken newRefreshTokenEntity = new RefreshToken();
            newRefreshTokenEntity.setValue(newRefreshToken);
            newRefreshTokenEntity.setMemberId(memberId);
            refreshTokenService.addRefreshToken(newRefreshTokenEntity);

            return newRefreshToken;
        } else {
            // 회원이 존재하지 않는 경우 처리
            throw new IllegalArgumentException("해당 사용자가 없습니다.");
        }
	}	
}
	    
		/*
		 * // 로그인 로직 public MemberLoginResponseDto login(MemberLoginDto loginDto) {
		 * Member member = memberService.findByEmail(loginDto.getEmail()); // 비밀번호 확인 및
		 * JWT 생성 로직... }
		 * 
		 * // 로그아웃 로직 public void logout(RefreshTokenDto refreshTokenDto) {
		 * refreshTokenService.deleteRefreshToken(refreshTokenDto.getRefreshToken()); //
		 * 추가적인 로그아웃 처리... }
		 * 
		 * // 리프레시 토큰 갱신 로직 public MemberLoginResponseDto refreshToken(RefreshTokenDto
		 * refreshTokenDto) { // 리프레시 토큰 검증 및 새로운 토큰 생성 로직... }
		 * 
		 * // 토큰 로테이션 로직 public void rotateToken(RefreshTokenDto refreshTokenDto) { //
		 * 토큰 로테이션 처리 로직... }
		 */

