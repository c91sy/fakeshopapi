package com.example.fakeshopapi.controller;

import com.example.fakeshopapi.domain.Member;
import com.example.fakeshopapi.domain.RefreshToken;
import com.example.fakeshopapi.domain.Role;
import com.example.fakeshopapi.dto.*;
import com.example.fakeshopapi.excption.UserNotFoundException;
import com.example.fakeshopapi.security.jwt.exception.JwtExceptionCode;
import com.example.fakeshopapi.security.jwt.util.IfLogin;
import com.example.fakeshopapi.security.jwt.util.JwtTokenizer;
import com.example.fakeshopapi.security.jwt.util.LoginUserDto;
import com.example.fakeshopapi.service.MemberService;
import com.example.fakeshopapi.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
//import jakarta.validation.Valid;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor 	//final 필드 및 @NonNull 필드에 대한 생성자를 자동으로 생성
@Validated  				//전체 클래스 레벨에서 유효성 검사를 활성화
//@Valid 			개별 객체나 클래스 내의 필드에 적용, 개별 객체의 유효성 검사
@RequestMapping("/members") //이 컨트롤러에서 처리하는 모든 엔드포인트는 "/members"로 시작 (http://localhost:8081/members/)
public class MemberController {

    private final JwtTokenizer jwtTokenizer;
    private final MemberService memberService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private static final Logger log = LoggerFactory.getLogger(MemberController.class);
// final이 아닐때 생성자
//    public MemberController(JwtTokenizer jwtTokenizer, MemberService memberService, RefreshTokenService refreshTokenService, PasswordEncoder passwordEncoder) {
//        this.jwtTokenizer = jwtTokenizer;
//        this.memberService = memberService;
//        this.refreshTokenService = refreshTokenService;
//        this.passwordEncoder = passwordEncoder;
//    }

//ResponseEntity 비동기 처리 시 응답을 제어해야 할 때 또는 RESTful API를 구현할 때 유용 (signup 메서드는 비동기 처리를 사용하지 않고 동기적으로 작동한다는 점을 기억)    
    @PostMapping("/signup")	//@RequestBody에 {name, email, password} 이런 dto의 데이터를 보낸다 (컨트롤러의 dto는 외부로 부터 오는 값을 받아들이기 위한 용도)
    public ResponseEntity signup(@RequestBody @Valid MemberSignupDto memberSignupDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {	//@Valid = 객체나 필드에 대한 유효성 검증을 트리거, BindingResult는 실패시(오류시) 유효성 검증 결과를 저장하는 객체 (성공시 아무동작을 안함)
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }//회원 정보 생성: 첫 번째 블록은 클라이언트의 입력을 기반으로 회원 정보를 준비하는 단계
        Member member = new Member();
        member.setName(memberSignupDto.getName());
        member.setEmail(memberSignupDto.getEmail());
        member.setPassword(passwordEncoder.encode(memberSignupDto.getPassword()));
        member.setBirthYear(Integer.parseInt(memberSignupDto.getBirthYear()));
        member.setBirthMonth(Integer.parseInt(memberSignupDto.getBirthMonth()));
        member.setBirthDay(Integer.parseInt(memberSignupDto.getBirthDay()));
        member.setGender(memberSignupDto.getGender());

//회원 정보를 데이터베이스에 저장하고, 저장된 정보를 바탕으로 클라이언트에게 반환할 응답을 준비하는 단계
        Member saveMember = memberService.addMember(member);

        MemberSignupResponseDto memberSignupResponse = new MemberSignupResponseDto();
        memberSignupResponse.setMemberId(saveMember.getMemberId());
        memberSignupResponse.setName(saveMember.getName());
        memberSignupResponse.setRegdate(saveMember.getRegdate());
        memberSignupResponse.setEmail(saveMember.getEmail());

        // 회원가입
        return new ResponseEntity(memberSignupResponse, HttpStatus.CREATED);
    }


    @GetMapping("/info")
    public ResponseEntity userinfo(@IfLogin LoginUserDto loginUserDto) {
        Member member = memberService.findByEmail(loginUserDto.getEmail());
        return new ResponseEntity(member, HttpStatus.OK);
    }
    
    

}
