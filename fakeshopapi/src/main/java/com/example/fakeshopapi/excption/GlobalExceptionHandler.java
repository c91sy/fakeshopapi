package com.example.fakeshopapi.excption;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

//ControllerAdvice 어노테이션: 모든 컨트롤러에서 발생하는 예외를 처리할 수 있는 클래스임을 나타냄
@ControllerAdvice
public class GlobalExceptionHandler {

 // UserNotFoundException 예외가 발생했을 때 호출되는 메서드
 @ExceptionHandler(UserNotFoundException.class)
 public ResponseEntity<String> handleUserNotFoundException(UserNotFoundException ex) {
     // 예외 메시지를 포함하여 404 NOT FOUND 상태 코드와 함께 응답 반환
     return new ResponseEntity<>(ex.getMessage(), HttpStatus.NOT_FOUND);
 }
 
 // SomeOtherException 예외가 발생했을 때 호출되는 메서드
 @ExceptionHandler(SomeOtherException.class)
 public ResponseEntity<String> handleSomeOtherException(SomeOtherException ex) {
     // 예외 메시지를 포함하여 적절한 상태 코드와 함께 응답 반환
     return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
 }
}

/*  타입 지정 없이도 작동하지만, 타입 안전성, 개발 경험 향상, 그리고 프로젝트 품질 향상을 위해 제네릭 타입 사용을 권장한다고 한다.
public ResponseEntity<String> handleUserNotFoundException(UserNotFoundException ex) {
    // 예외 메시지를 포함하여 404 NOT FOUND 상태 코드와 함께 응답 반환
    return new ResponseEntity<>(ex.getMessage(), HttpStatus.NOT_FOUND);
*/