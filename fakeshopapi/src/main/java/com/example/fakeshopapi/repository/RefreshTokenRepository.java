package com.example.fakeshopapi.repository;

import com.example.fakeshopapi.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByValue(String value);
    
 // memberId로 리프레시 토큰을 찾는 메서드 추가
    Optional<RefreshToken> findByMemberId(Long memberId);
}


/**
  Access Token 저장 필요 없음: Access Token을 메모리에서 관리하고 클라이언트에게 전달하는 경우,
  별도의 AccessTokenRepository는 필요 없습니다
 */