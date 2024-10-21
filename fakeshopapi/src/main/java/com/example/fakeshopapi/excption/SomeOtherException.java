package com.example.fakeshopapi.excption;

public class SomeOtherException extends RuntimeException {
	public SomeOtherException(String message) {
        super(message);
    }

    public SomeOtherException(String message, Throwable cause) {
        super(message, cause);
    }

}
