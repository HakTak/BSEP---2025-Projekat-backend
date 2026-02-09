package com.bezbednost.sertifikat.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.annotation.JsonBackReference;

@Entity
@Table(name = "certificate_templates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id", nullable = false)
    @JsonBackReference
    private Certificate issuer;

    @Column(nullable = false)
    private String cnRegex;

    @Column(nullable = false)
    private String sanRegex;

    @Column(nullable = false)
    private Integer maxTtlInDays;

    @Column(nullable = true)
    private Integer keyUsageBitmask;

    @Column(nullable = true, columnDefinition = "TEXT")
    private String extendedKeyUsageOids;

    @Column(nullable = true)
    private String description;

    @Column(nullable = false, columnDefinition = "BOOLEAN DEFAULT true")
    private Boolean active = true;
}
