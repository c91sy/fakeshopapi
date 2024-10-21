package com.example.fakeshopapi.domain;

import javax.persistence.*;
//import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name="refresh_token")
@NoArgsConstructor
@Setter
@Getter
public class RefreshToken {
    @Id // 이 필드가 Table의 PK.
    @GeneratedValue(strategy = GenerationType.IDENTITY) //Id는 자동으로 생성되도록 한다. 1,2,3,4
    private Long id;
    private Long memberId;
    private String value;
}
//refresh_token 테이블에 id, memberId, value를 저장하기 위한 jpa엔티티