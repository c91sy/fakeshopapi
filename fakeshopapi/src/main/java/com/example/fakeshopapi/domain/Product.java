package com.example.fakeshopapi.domain;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
//import jakarta.persistence.*;

@Entity
@Table(name = "product")
@Setter
@Getter
public class Product {

    @Id // 이 필드가 Table의 PK.
    @GeneratedValue(strategy = GenerationType.IDENTITY) //Id는 자동으로 생성되도록 한다. 1,2,3,4
    private Long id; //상품id

    private String title; //상품명

    private Double price; //상품가격

    private String description; //상품설명

    @ManyToOne // 다대일 관계: 여러 상품이 하나의 카테고리에 속할 수 있음
    @JoinColumn(name = "category_id") // "category_id"라는 외래 키로 매핑
    private Category category; //어떤 상품카테고리 인지

    private String imageUrl; //상품 이미지 URL

    @Embedded  //Rating 클래스에 정의된 필드(칼럼)들이 Product 클래스에 포함되어 데이터베이스 테이블에 나열
    private Rating rating; //상품의 평점 정보
}

