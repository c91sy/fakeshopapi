package com.example.fakeshopapi.domain;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
//import jakarta.persistence.*;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

//장바구니
@Entity
@Table(name = "cart")
@Setter
@Getter
public class Cart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) //Id는 자동으로 생성되도록 한다. 1,2,3,4
    private Long id; //사용자 마다 매일 장바구니에 담기 할때 마다 새로운 카트 id가 만들어지는것

    private Long memberId; //JWT 토큰에서 추출한 사용자 ID로, 장바구니에 물건을 담은 사용자를 식별합니다.

    private LocalDate date; // yyyymmdd

    @JsonManagedReference //cascade = CascadeType.ALL은 영속성 컨텍스트에서 수행되는 모든 작업(추가, 삭제, 업데이트 등)
    @OneToMany(mappedBy = "cart", cascade = CascadeType.ALL) //1:n 관계 
    private List<CartItem> cartItems = new ArrayList<>(); //CartItem 객체의 리스트를 초기화합니다. 이 리스트는 장바구니에 담긴 여러 항목들을 나타냄

 // 장바구니의 총 가격 계산하는 메서드 (변수를 선언하면서 그 값을 0.0으로 초기화) a += b는 a = a + b
    public double TotalPrice() {
        double totalPrice = 0.0;
        for (CartItem item : cartItems) {
            totalPrice += item.getProductPrice() * item.getQuantity();
        }
        return totalPrice;
 }
}
//JWT 값이 달라진다고 해서 memberId가 변경되는 것은 아니며, 따라서 장바구니 조회 시 에러가 발생하지 않습니다.
//JWT의 역할은 사용자를 인증하는 것이고, 장바구니와 같은 리소스는 memberId를 통해 연결되므로, 사용자 식별은 안전하게 유지

/* 람다식일 경우
public double TotalPrice() {
return cartItems.stream()
        .mapToDouble(item -> item.getProductPrice() * item.getQuantity())//가격과 수량 필드 곱하기
        .sum();
}
*/