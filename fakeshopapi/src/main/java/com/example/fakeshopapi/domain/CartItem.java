package com.example.fakeshopapi.domain;

import com.fasterxml.jackson.annotation.JsonBackReference;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
//import jakarta.persistence.*;

@Entity
@Table(name = "cart_item")
@Setter
@Getter
public class CartItem {

    @Id // 이 필드가 Table의 PK.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Id는 자동으로 생성되도록 한다. 1,2,3,4
    private Long id;
    
    @JsonBackReference
    @ManyToOne
    @JoinColumn(name = "cart_id")
    private Cart cart;
    
    private Long productId; //상품id

    private String productTitle; //상품명

    private Double productPrice; //상품가격

    private String productDescription; //상품설명

    private int quantity; //수량
    
    //private Long cartId; // 장바구니 ID (어떤 장바구니에 속하는지 명확해져 후속 작업(조회, 결제 등)을 쉽게 할 수 있다.)

}
