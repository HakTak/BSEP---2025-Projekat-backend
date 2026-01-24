package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.SubjectDTO;
import com.bezbednost.sertifikat.model.Subject;
import com.bezbednost.sertifikat.service.SubjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/subjects")
public class SubjectController {

    @Autowired
    private SubjectService subjectService;

    // GET: https://localhost:8443/api/subjects
    @GetMapping
    public List<Subject> getAll() {
        return subjectService.getAllSubjects();
    }

    // POST: https://localhost:8443/api/subjects
    @PostMapping
    public ResponseEntity<Subject> create(@RequestBody SubjectDTO subjectDTO) {
        Subject created = subjectService.createSubject(subjectDTO);
        return ResponseEntity.ok(created);
    }
}