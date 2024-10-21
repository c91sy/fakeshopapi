package com.example.fakeshopapi.security.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class JwtTokenizer {
// 토큰 생성, 파싱 및 유효성 검사와 같은 유틸리티 기능을 담당
/*"파싱(parsing)"은 데이터를 분석하고 구조화된 형식으로 변환하는 과정을 의미함.
   주로 컴퓨터 프로그래밍 및 데이터 처리에서 사용되며, 입력된 데이터의 내용을 이해하고 필요한 정보를 추출하는 데에 사용*/
// Access Token 연장 및 Refresh Token 로테이션은 사용자의 인증 상태를 관리하는 비즈니스 로직에 해당 (AuthService)
    private final byte[] accessSecret;
    private final byte[] refreshSecret;

    public final Long accessTokenExpireCount; //30 * 60 * 1000L; // 30 minutes 요즘은 yml파일에 작성
    public final Long refreshTokenExpireCount; //24 * 60 * 60 * 1000L; // 1 days */

    public JwtTokenizer(
    		@Value("${jwt.secretKey}") String accessSecret, 
            @Value("${jwt.refreshKey}") String refreshSecret,
            @Value("${jwt.accessTokenExpireCount}") Long accessTokenExpireCount, // 추가
            @Value("${jwt.refreshTokenExpireCount}") Long refreshTokenExpireCount // 추가
    		) 
    {
        this.accessSecret = accessSecret.getBytes(StandardCharsets.UTF_8);
        this.refreshSecret = refreshSecret.getBytes(StandardCharsets.UTF_8);
        this.accessTokenExpireCount = accessTokenExpireCount; // 추가
        this.refreshTokenExpireCount = refreshTokenExpireCount; // 추가
    }

    /**
     * AccessToken 생성
     */
    public String createAccessToken(Long id, String email, String name, List<String> roles) {
        return createToken(id, email, name, roles, accessTokenExpireCount, accessSecret);
    }
    
    /**
     * RefreshToken 생성
     */
    public String createRefreshToken(Long id, String email, String name, List<String> roles) {
        return createToken(id, email, name, roles, refreshTokenExpireCount, refreshSecret);
    }

    /**
     * 토큰 생성 메서드
     */
    private String createToken(Long id, String email, String name, List<String> roles,
                               Long expire, byte[] secretKey) {
        Claims claims = Jwts.claims().setSubject(email);

        claims.put("roles", roles);
        claims.put("memberId", id);
        claims.put("name", name);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + expire))
                .signWith(getSigningKey(secretKey))
                .compact();
    }

    /**
     * 토큰에서 유저 아이디 얻기
     */
    public Long getMemberIdFromToken(String token) {
        String[] tokenArr = token.split(" ");
        token = tokenArr[1];
        Claims claims = parseToken(token, accessSecret);
        return Long.valueOf((Integer)claims.get("memberId"));
    }

    public Claims parseAccessToken(String accessToken) {
        return parseToken(accessToken, accessSecret);
    }

    public Claims parseRefreshToken(String refreshToken) {
        return parseToken(refreshToken, refreshSecret);
    }


    public Claims parseToken(String token, byte[] secretKey) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(secretKey))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * @param secretKey - byte형식
     * @return Key 형식 시크릿 키
     */
    public static Key getSigningKey(byte[] secretKey) {
        return Keys.hmacShaKeyFor(secretKey);
    }

 // 액세스 토큰 시크릿 키를 안전하고 효율적으로 관리하기 위해 반환 (유틸리티 메서드)
    public String getAccessSecret() {
        return new String(accessSecret, StandardCharsets.UTF_8);
    }
 // 리프레시 토큰 시크릿 키를 안전하고 효율적으로 관리하기 위해 반환 (유틸리티 메서드)
    public String getRefreshSecret() {
        return new String(refreshSecret, StandardCharsets.UTF_8);
    }
 // 추가된 메서드: 토큰의 만료 여부 확인
    public boolean isTokenExpired(String token, String secretKey) {
        try {
            Claims claims = parseToken(token, secretKey.getBytes(StandardCharsets.UTF_8));
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            log.error("토큰 파싱 중 오류 발생: {}", e.getMessage());
            return true; // 예외 발생 시 만료된 것으로 간주
        }
    }

}

//Claims 객체는 JwtTokenizer 내에서 JWT를 생성하고 파싱하는 데 사용되며, 이 클래스 외부에서는 일반적으로 사용되지 않습니다.
//다른 서비스나 클래스에서는 JwtTokenizer의 메서드를 호출하여 클레임 정보를 얻거나 JWT를 생성하는 방식으로 간접적으로 사용
