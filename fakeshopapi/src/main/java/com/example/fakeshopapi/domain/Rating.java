package com.example.fakeshopapi.domain;

import javax.persistence.Embeddable;
//import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;


@Embeddable
@Setter
@Getter
public class Rating {
    private Double rate; //평점
    private Integer count; //평점 수
}

