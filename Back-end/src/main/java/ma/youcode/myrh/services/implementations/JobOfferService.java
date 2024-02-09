package ma.youcode.myrh.services.implementations;

import jakarta.persistence.EntityNotFoundException;
import ma.youcode.myrh.dtos.JobOfferDTO;
import ma.youcode.myrh.dtos.RecruiterDTO;
import ma.youcode.myrh.dtos.ResumeDTO;
import ma.youcode.myrh.models.JobOffer;
import ma.youcode.myrh.models.Recruiter;
import ma.youcode.myrh.models.Resume;
import ma.youcode.myrh.models.Status;
import ma.youcode.myrh.repositories.IJobOfferRepository;
import ma.youcode.myrh.repositories.IRecruiterRepository;
import ma.youcode.myrh.repositories.IResumeRepository;
import ma.youcode.myrh.services.IJobOfferService;
import ma.youcode.myrh.utils.EmailService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class JobOfferService implements IJobOfferService {
    @Autowired
    IJobOfferRepository jobOfferRepository;
    @Autowired
    IResumeRepository resumeRepository;
    @Autowired
    IRecruiterRepository recruiterRepository;
    @Autowired
    ModelMapper modelMapper;

    @Override
    public JobOfferDTO save(JobOfferDTO jobOfferDTO, long recruiterId) {
        Optional<Recruiter> recruiter = recruiterRepository.findById(recruiterId);

        JobOffer jobOffer = modelMapper.map(jobOfferDTO, JobOffer.class);

        jobOffer.setRecruiter(recruiter.get());
        jobOffer = jobOfferRepository.save(jobOffer);

        return modelMapper.map(jobOffer, JobOfferDTO.class);
    }

    @Override
    public List<JobOfferDTO> findByRecruiterId(long id) {
        Recruiter recruiterDTO = recruiterRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("recruiter not found"));
        List<JobOffer> jobOffers = jobOfferRepository.findByRecruiter(modelMapper.map(recruiterDTO, Recruiter.class));

        return jobOffers.stream()
                .map(jobOffer -> modelMapper.map(jobOffer, JobOfferDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public List<JobOfferDTO> findByTitle(String title) {
        List<JobOffer> jobOffers = jobOfferRepository.findByTitleContainsIgnoreCase(title);
        return jobOffers.stream()
                .map(jobOffer -> modelMapper.map(jobOffer, JobOfferDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public Page<JobOfferDTO> findAllPageable(Pageable pageable) {
        Page<JobOffer> jobOffers = jobOfferRepository.findAll(pageable);
        return jobOffers.map(jobOffer -> modelMapper.map(jobOffer, JobOfferDTO.class));
    }

    @Override
    public List<JobOfferDTO> findAll() {
        List<JobOffer> jobOffers = jobOfferRepository.findAll();
        return jobOffers.stream()
                .map(jobOffer -> modelMapper.map(jobOffer, JobOfferDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public List<JobOfferDTO> findAllByUserId(long id) {
        List<JobOffer> jobOffers = jobOfferRepository.findByResumes_User_Id(id);
        return jobOffers.stream()
                .map(jobOffer -> modelMapper.map(jobOffer, JobOfferDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public List<JobOfferDTO> findAllByStatus(String status) {
        List<JobOffer> jobOffers = jobOfferRepository.findByStatus(Enum.valueOf(Status.class, status));
        return jobOffers.stream()
                .map(jobOffer -> modelMapper.map(jobOffer, JobOfferDTO.class))
                .collect(Collectors.toList());
    }


    @Override
    public String updateStatus(long id, Status newStatus) {
        Optional<JobOffer> jobOfferOptional = jobOfferRepository.findById(id);
        if (jobOfferOptional.isPresent()) {
            JobOffer jobOffer = jobOfferOptional.get();
            jobOffer.setStatus(newStatus);

            jobOfferRepository.save(jobOffer);
            return newStatus.name();
        }

        return null;
    }


}