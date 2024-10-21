package com.example.fakeshopapi.excption;
						
public class UserNotFoundException extends RuntimeException {
    // 생성자: 예외 메시지를 인자로 받아 부모 클래스인 RuntimeException에 전달 (Java 표준 라이브러리에서 제공하는 클래스이기 때문에, 이미 Java의 java.lang 패키지에 포함)
    public UserNotFoundException(String message) {
        super(message); // 부모 클래스의 생성자를 호출하여 메시지를 설정
    }
}