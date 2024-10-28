package com.example.fakeshopapi.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotEmpty;
//import jakarta.validation.constraints.*;

@Getter
@Setter
@NoArgsConstructor  // 기본 생성자 자동 생성
@AllArgsConstructor // 모든 필드를 매개변수로 받는 생성자 추가
public class RefreshTokenDto {
    @NotEmpty // 이 필드는 비어 있으면 안 됩니다.
    private String refreshToken;
}

//리플레시 토큰 값