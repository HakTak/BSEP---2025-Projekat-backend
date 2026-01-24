package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.SubjectDTO;
import com.bezbednost.sertifikat.model.Subject;
import com.bezbednost.sertifikat.repository.SubjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SubjectService {

    @Autowired
    private SubjectRepository subjectRepository;

    // Čitanje svih iz baze
    public List<Subject> getAllSubjects() {
        return subjectRepository.findAll();
    }

    // Upis u bazu
    public Subject createSubject(SubjectDTO dto) {
        Subject newSubject = new Subject(dto.getEmail(), dto.getCommonName(), dto.getOrganization());
        return subjectRepository.save(newSubject);
    }
}