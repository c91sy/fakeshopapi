package com.example.fakeshopapi.service;

import com.example.fakeshopapi.domain.Member;
import com.example.fakeshopapi.domain.Role;
import com.example.fakeshopapi.repository.MemberRepository;
import com.example.fakeshopapi.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final RoleRepository roleRepository;    
//새로운 회원을 추가
    @Transactional
    public Member addMember(Member member) {
        Optional<Role> userRole = roleRepository.findByName("ROLE_USER");
        member.addRole(userRole.get()); // 기본 역할 설정
        Member saveMember = memberRepository.save(member); // 회원 저장
        return saveMember;
    }
    
//회원 정보 수정
    @Transactional
    public Member updateMember(Member member) {
        return memberRepository.save(member); // 수정된 회원 정보 저장
    }

//회원 탈퇴
    @Transactional
    public void deleteMember(Long memberId) {
        memberRepository.deleteById(memberId); // 회원 삭제
    }
//비밀번호 변경
    @Transactional
    public void changePassword(Long memberId, String newPassword) {
        Member member = memberRepository.findById(memberId)
            .orElseThrow(() -> new IllegalArgumentException("해당 사용자가 없습니다."));
        member.setPassword(newPassword); // 비밀번호 변경
        memberRepository.save(member); // 변경 사항 저장
    }
  
//주어진 ID로 회원 정보를 조회
    @Transactional(readOnly = true)
    public Optional<Member> getMember(Long memberId){
        return memberRepository.findById(memberId);
    }
    
//주어진 이메일로 회원 정보를 조회, 결과가 없으면 Optional.empty() 반환 (getMember은 조회만 필요한 경우에 유용)
//(회원 정보가 있을 수도 없을 수도 있는 경우에 사용)예를 들어, 회원 정보가 선택 사항인 경우나, 결과가 없더라도 에러를 발생시키지 않고 부드럽게 처리    
    @Transactional(readOnly = true) //Optional<Member>을 사용하면 null 체크 없이 안전하게 값을 다룰 수 있다
    public Optional<Member> getMember(String email){
        return memberRepository.findByEmail(email);
    }
//주어진 이메일로 회원 정보를 조회, Member 객체를 직접 반환 즉 결과가 없으면 예외 발생 (로그인시 사용)
    @Transactional(readOnly = true)
    public Member findByEmail(String email){
        return memberRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("해당 사용자가 없습니다."));
    }
}
