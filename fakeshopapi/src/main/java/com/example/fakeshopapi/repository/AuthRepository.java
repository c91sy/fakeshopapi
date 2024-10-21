package com.example.fakeshopapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.fakeshopapi.domain.Member;

public interface AuthRepository extends JpaRepository<Member, Long> {

}
