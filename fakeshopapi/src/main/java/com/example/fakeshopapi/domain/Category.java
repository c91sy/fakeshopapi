package com.example.fakeshopapi.domain;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
//import jakarta.persistence.*;

@Entity
@Table(name = "category") //상품이 담겨있는 카테고리 ex전자제품 -> 냉장고, 세탁기 등
@Setter
@Getter
public class Category {

    @Id // 이 필드가 Table의 PK.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 기본 키의 값을 자동 생성 (주로 MySQL에서 사용)
    private Long id;

    private String name;

}
