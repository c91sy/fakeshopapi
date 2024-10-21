package com.example.fakeshopapi.service;

import com.example.fakeshopapi.domain.RefreshToken;
import com.example.fakeshopapi.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
/**리프레시 토큰 추가*/
    @Transactional
    public RefreshToken addRefreshToken(RefreshToken refreshToken) {
    	 try {
    	        log.debug("리프레시 토큰 저장 요청: {}", refreshToken);
    	        return refreshTokenRepository.save(refreshToken);
    	    } catch (Exception e) {
    	        log.error("리프레시 토큰 저장 중 오류 발생: {}", e.getMessage());
    	        throw e; // 예외를 다시 던져서 트랜잭션 롤백
    	    }
    }
/**리프레시 토큰 삭제*/
    @Transactional
    public void deleteRefreshToken(String refreshToken) {
        refreshTokenRepository.findByValue(refreshToken).ifPresent(refreshTokenRepository::delete);
    }
/**리프레시 토큰 조회*/
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findRefreshToken(String refreshToken) {
        return refreshTokenRepository.findByValue(refreshToken);
    }
    
/** memberId로 리프레시 토큰 조회 */
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findRefreshTokenByMemberId(Long memberId) {
        return refreshTokenRepository.findByMemberId(memberId);
    }
}


//서비스의 역할: 서비스 클래스는 비즈니스 로직과 데이터베이스 작업을 처리하는 데 중점을 두며, Refresh Token을 데이터베이스에 저장하고 관리하는 기능을 담당
//JWT와 관련된 직접적인 처리는 JwtTokenizer에서 수행하는 것이 바람직
//AccessTokenService는 필요없다 : Access Token을 클라이언트 측에서 직접 관리하기 때문에

/**JwtTokenizer 클래스 : 해당 메서드들은 JWT의 생성 및 유효성 검사와 관련된 기능을 제공
- 토큰 생성: Access Token 및 Refresh Token을 생성하는 메서드를 포함합니다.
- 토큰 파싱: JWT를 파싱하여 Claims를 추출하고, 유효성을 검사합니다.
- 비밀 키 관리: 토큰의 서명을 위한 비밀 키를 관리합니다.
- 만료 여부 확인: 토큰이 만료되었는지 확인하는 기능을 제공합니다.
 즉, JwtTokenizer는 JWT의 생명 주기와 관련된 모든 기능을 처리
 */