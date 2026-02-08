package com.bezbednost.sertifikat.utils; // Ili com.bezbednost.sertifikat.service

import org.springframework.stereotype.Component;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class PasswordGenerator {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final int MIN_LENGTH = 12;

    private final SecureRandom random = new SecureRandom();

    public String generateStrongPassword() {
        StringBuilder password = new StringBuilder();

        // Osiguraj bar jedan karakter iz svake kategorije
        password.append(getRandomChar(LOWER));
        password.append(getRandomChar(UPPER));
        password.append(getRandomChar(DIGITS));
        password.append(getRandomChar(SPECIAL));

        // Popuni do minimalne dužine nasumičnim karakterima iz svih kategorija
        String allChars = LOWER + UPPER + DIGITS + SPECIAL;
        for (int i = 4; i < MIN_LENGTH; i++) {
            password.append(getRandomChar(allChars));
        }

        // Izmešaj karaktere da ne bi uvek išli istim redosledom
        return shuffleString(password.toString());
    }

    private char getRandomChar(String source) {
        return source.charAt(random.nextInt(source.length()));
    }

    private String shuffleString(String input) {
        List<Character> characters = input.chars()
                .mapToObj(c -> (char) c)
                .collect(Collectors.toList());
        Collections.shuffle(characters);
        StringBuilder sb = new StringBuilder();
        characters.forEach(sb::append);
        return sb.toString();
    }
}