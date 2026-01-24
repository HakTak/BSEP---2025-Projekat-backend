package com.bezbednost.sertifikat.model;

import jakarta.persistence.*;
import lombok.Data; // Lombok za gettere i settere
import lombok.NoArgsConstructor;

@Entity
@Table(name = "subjects") // Ime tabele u bazi
@Data
@NoArgsConstructor
public class Subject {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String commonName; // Ime i prezime ili naziv organizacije

    @Column(nullable = false)
    private String organization;

    // Konstruktor bez ID-a za lakše kreiranje
    public Subject(String email, String commonName, String organization) {
        this.email = email;
        this.commonName = commonName;
        this.organization = organization;
    }
}