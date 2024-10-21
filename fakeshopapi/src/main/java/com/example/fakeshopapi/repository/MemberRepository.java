package com.example.fakeshopapi.repository;

import com.example.fakeshopapi.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email); //이메일로 회원을 찾아주는 커스텀 쿼리 메소드 (사용자정의메소드)
}


//Spring Data JPA의 Repository 인터페이스를 상속받아 만든 Member 엔티티를 위한 데이터 접근 객체(DAO)