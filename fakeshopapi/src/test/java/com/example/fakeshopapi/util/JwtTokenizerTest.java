package com.example.fakeshopapi.util;

import com.example.fakeshopapi.security.jwt.util.JwtTokenizer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@SpringBootTest
public class JwtTokenizerTest {
    @Autowired
    JwtTokenizer jwtTokenizer;

    @Value("${jwt.secretKey}") // application.yml파일의 jwt: secretKey: 값
    String accessSecret; // "12345678901234567890123456789012"
    public final Long ACCESS_TOKEN_EXPIRE_COUNT = 30 * 60 * 1000L; // 60 * 1000 * 30 // 30분짜리 이용권	7 * 24 * 60 * 60 * 1000L; 이건 7일
// 사이트를 더 이용하고 싶으면 리플레쉬토큰(7일짜리 이용권)으로 다시 엑세스 토큰을 발급 받아야한다
/*(클라이언트는 리프레시 토큰을 사용하여 새로운 엑세스 토큰을 발급받는다 이 과정에서 리프레시 토큰의 유효 기간은 갱신되지 않는다)*/
// 로그아웃시 리플레쉬 토큰이 지워지고 새로 로그인하기 전에는 리플레쉬 토큰이 안 만들어지기 때문에 더이상 연장 불가 (쉽게 말해 7일 후 자동로그아웃)
/*리플레시 토큰을 별도의 DTO와 도메인 클래스로 분리 <자동 로그아웃 구현> (코드의 모듈화와 재사용성을 높이는 좋은 프랙티스)*/
    @Test
    public void createToken() throws Exception{ // JWT 토큰을 생성. (지속 시간이 짧다 30분)
        String email = "ch91sy@gmail.com";
        List<String> roles = List.of("ROLE_USER"); // [ "ROLE_USER" ]
        Long id = 1L;
        Claims claims = Jwts.claims().setSubject(email); // JWT 토큰의 payload에 들어갈 내용(claims)을 설정.
        // claims -- sub -- email          		(이미 있는 값은 set)
        // claims -- roles -- [ "ROLE_USER" ]	(이미 없는 값은  put)
        // claims -- memberId -- 1L				(이미 없는 값은  put)
        claims.put("roles", roles);
        claims.put("memberId", id);

        // application.yml파일의 jwt: secretKey: 값
        byte[] accessSecret = this.accessSecret.getBytes(StandardCharsets.UTF_8);

        // JWT를 생성하는 부분.
        String JwtToken = Jwts.builder() // builder는 JwtBuilder를 반환(리턴). Builder패턴.
                .setClaims(claims) // claims가 추가된 JwtBuilder를 리턴.
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + this.ACCESS_TOKEN_EXPIRE_COUNT)) // 현재시간으로부터 30분뒤에 만료.
                .signWith(Keys.hmacShaKeyFor(accessSecret)) // 결과에 서명까지 포함시킨 JwtBuilder리턴.
                .compact();

        System.out.println(JwtToken);
    }
    
    //생성된 토큰  (email c91sy@gmail) 
// eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjOTFzeUBnbWFpbC5jb20iLCJyb2xlcyI6WyJST0xFX1VTRVIiXSwidXNlcklkIjoxLCJpYXQiOjE2NzUyNTg1MTYsImV4cCI6MTY3NTI2MDMxNn0.j4pKSr0F6Ardh7keO5XPedO_2z1Lg6aSyR8aLIX1RKg
    
    //email을 ch91sy@gmail로 할 경우	    
// eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaDkxc3lAZ21haWwuY29tIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sInVzZXJJZCI6MSwiaWF0IjoxNjc1MjU4NTE2LCJleHAiOjE2NzUyNjAzMTZ9.Gw565YCOApi_D8b5FE3FeMh-ZcZ1hmdPh9tlRbT8v14
    
    @Test	// JWT 토큰 유효성 검증 및 파싱 테스트 (파싱은 데이터를 구조화된 형식으로 분석하고 해석하는 과정)
    public void parseToken() throws Exception{
        byte[] accessSecret = this.accessSecret.getBytes(StandardCharsets.UTF_8); //roles에 "ADMIN_USER" 추가
        String jwtToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaDkxc3lAZ21haWwuY29tIiwicm9sZXMiOlsiUk9MRV9VU0VSIiwiQURNSU5fVVNFUiJdLCJ1c2VySWQiOjEsImlhdCI6MTY3NTI1ODUxNiwiZXhwIjoxNjc1MjYwMzE2fQ.LZavmMNO7ejsZXk7rUTPxXT008EQae9OXXTY2XGjDsk";

        Claims claims = Jwts.parserBuilder() // JwtParserBuilder를 반환.
                .setSigningKey(Keys.hmacShaKeyFor(accessSecret))
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
        System.out.println(claims.getSubject());
        System.out.println(claims.get("roles"));
        System.out.println(claims.get("memberId"));
        System.out.println(claims.getIssuedAt()); //발행시간
        System.out.println(claims.getExpiration()); //만료시간
    }

    @Test // 새로운 JWT 토큰을 생성 및 구조 확인 테스트
    public void createJWT(){
        String jwtToken = jwtTokenizer.createAccessToken(1L, "ch91sy@gmail.com", "최세영", List.of("ROLE_USER"));
        System.out.println(jwtToken);
    }

    @Test // 기존 JWT 토큰 파싱 및 내용 접근 기능 테스트
    public void parseJWT(){
        Claims claims = jwtTokenizer.parseAccessToken("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaDkxc3lAZ21haWwuY29tIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sInVzZXJJZCI6MSwiaWF0IjoxNjc1MjQzODg3LCJleHAiOjE2NzUyNDU2ODd9.Ygpjt1UNx5tvdkGQBuiIdgSr_FEt9bWEmzHfivVUyDA");
        System.out.println(claims.getSubject());
        System.out.println(claims.get("roles"));
        System.out.println(claims.get("memberId"));
    }
}

// eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaDkxc3lAZ21haWwuY29tIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sInVzZXJJZCI6MSwiaWF0IjoxNjc1MjQzMzIyLCJleHAiOjE2NzUyNDUxMjJ9.4VJKDtaiVie3yDzneYsGy-OkbLaVrqO_dz4Qq2LoRn8
// eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaDkxc3lAZ21haWwuY29tIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sInVzZXJJZCI6MSwiaWF0IjoxNjc1MjQzMzY2LCJleHAiOjE2NzUyNDUxNjZ9.m9DUj6Bvbob_E4_-15wdnmY472gb8FXaNt-QtjflLvs