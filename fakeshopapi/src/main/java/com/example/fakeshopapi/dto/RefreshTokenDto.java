package com.example.fakeshopapi.dto;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
//import jakarta.validation.constraints.*;

@Data
public class RefreshTokenDto {
    @NotEmpty // 이 필드는 비어 있으면 안 됩니다.
    private String refreshToken;
}

//리플레시 토큰 값