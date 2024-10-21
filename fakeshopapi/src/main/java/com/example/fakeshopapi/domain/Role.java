package com.example.fakeshopapi.domain;

import javax.persistence.*;
//import jakarta.persistence.Column;
//import jakarta.persistence.Entity;
//import jakarta.persistence.Id;
//import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Entity
@Table(name="role_shopping")
@NoArgsConstructor
@Setter
@Getter
public class Role {
    @Id // 이 필드가 Table의 PK.
    @Column(name="role_id")
    private Long roleId;

    @Column(length = 20)
    private String name;

    @Override
    public String toString() {
        return "Role{" +
                "roleId=" + roleId +
                ", name='" + name + '\'' +
                '}';
    }
}