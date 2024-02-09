package ma.youcode.myrh.controllers;


import ma.youcode.myrh.dtos.ResumeDTO;
import ma.youcode.myrh.models.ResumeStatus;
import ma.youcode.myrh.models.Status;
import ma.youcode.myrh.services.IResumeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequestMapping("api/v1/resumes")
@RestController
@CrossOrigin("*")
public class ResumeController {

    @Autowired
    IResumeService resumeService;

    @PostMapping("/{jobOfferId}")
    public ResponseEntity<ResumeDTO> create(@PathVariable long jobOfferId, @ModelAttribute ResumeDTO resumeToSave) {
        ResumeDTO resumeDTO = resumeService.save(resumeToSave, jobOfferId);
        return ResponseEntity.ok(resumeDTO);
    }


    @PostMapping("/{id}/{newStatus}")
    public ResponseEntity<ResumeDTO> update(@PathVariable long id, @PathVariable ResumeStatus newStatus) {
        ResumeDTO resumeDTO = resumeService.updateStatus(id, newStatus);
        return ResponseEntity.ok(resumeDTO);
    }

    @GetMapping()
    public ResponseEntity<List<ResumeDTO>> getAll() {
        List<ResumeDTO> resumes = resumeService.findAll();
        return ResponseEntity.ok(resumes);
    }

    @GetMapping("/byRecruiter/{id}")
    public ResponseEntity<List<ResumeDTO>> getAll(
            @PathVariable long id
    ) {
        List<ResumeDTO> resumes = resumeService.findAllByRecruiterId(id);
        return ResponseEntity.ok(resumes);
    }

    @GetMapping("/byUser/{id}")
    public ResponseEntity<List<ResumeDTO>> getAllByUser(
            @PathVariable long id
    ) {
        List<ResumeDTO> resumes = resumeService.findAllByUserId(id);
        return ResponseEntity.ok(resumes);
    }

    @GetMapping("/{jobOfferId}")
    public ResponseEntity<List<ResumeDTO>> getByJobOffer(
            @PathVariable long jobOfferId
    ) {
        List<ResumeDTO> resumes = resumeService.findByJobOffer(jobOfferId);
        return ResponseEntity.ok(resumes);
    }

}
