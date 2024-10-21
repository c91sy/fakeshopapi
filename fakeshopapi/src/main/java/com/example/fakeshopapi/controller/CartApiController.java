package com.example.fakeshopapi.controller;

import com.example.fakeshopapi.domain.Cart;
import com.example.fakeshopapi.security.jwt.util.IfLogin;
import com.example.fakeshopapi.security.jwt.util.LoginUserDto;
import com.example.fakeshopapi.service.CartService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@RestController
@RequestMapping("/carts") // http://localhost:8081/carts
@RequiredArgsConstructor
public class CartApiController {
    private final CartService cartService;
    @PostMapping
    public Cart addCart(@IfLogin LoginUserDto loginUserDto) {
        LocalDate date = LocalDate.now();
        Cart cart = cartService.addCart(loginUserDto.getMemberId(), date); // 카트를 추가하는 서비스 메서드를 호출
        return cart; // 생성된 카트를 반환
    }


}
