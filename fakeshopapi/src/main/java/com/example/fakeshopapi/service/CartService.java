package com.example.fakeshopapi.service;

import com.example.fakeshopapi.domain.Cart;
import com.example.fakeshopapi.repository.CartRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Optional;

@Service
@RequiredArgsConstructor // 모든 final 필드를 포함한 생성자를 자동으로 생성
public class CartService {
    private final CartRepository cartRepository;
    public Cart addCart(Long memberId, LocalDate date) {
        Optional<Cart> cart = cartRepository.findByMemberIdAndDate(memberId, date); // 주어진 memberId와 date로 카트를 조회
        if(cart.isEmpty()) {
            Cart newCart = new Cart();
            newCart.setMemberId(memberId);
            newCart.setDate(date);
            Cart saveCart = cartRepository.save(newCart); // 새로운 카트를 데이터베이스에 저장하고, 저장된 카트를 반환
            return saveCart;
        } else {
            return cart.get(); // 카트가 존재하는 경우, 기존 카트를 반환합니다.
        }
    }
}

//isEmpty(): 이 메서드는 Optional에 값이 없을 때 true를 반환