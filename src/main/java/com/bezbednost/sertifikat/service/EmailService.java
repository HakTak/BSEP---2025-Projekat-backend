package com.bezbednost.sertifikat.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    
    @Autowired
    private JavaMailSender mailSender;
    
    @Value("${spring.mail.username}")
    private String fromEmail;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    public void sendActivationEmail(String toEmail, String firstName, String activationToken) {
        String activationLink = frontendUrl + "/activate?token=" + activationToken;
        
        String subject = "Aktivacija nalog - BSEP Sertifikat";
        
        String body = "Pozdrav " + firstName + ",\n\n" +
                "Hvala što ste se registrovali! Kliknite na link ispod da aktivirate svoj nalog:\n\n" +
                activationLink + "\n\n" +
                "Link je validan 24 sata.\n\n" +
                "Ako niste koristili login, ignorišite ovaj email.\n\n" +
                "Srdačno,\n" +
                "BSEP Tim";
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        
        try {
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri slanju email-a: " + e.getMessage());
        }
    }
}
