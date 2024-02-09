package ma.youcode.myrh.repositories;

import ma.youcode.myrh.models.JobOffer;
import ma.youcode.myrh.models.Recruiter;
import ma.youcode.myrh.models.Status;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IJobOfferRepository extends JpaRepository<JobOffer, Long> {
    JobOffer save(JobOffer jobOffer);

    List<JobOffer> findByRecruiter(Recruiter recruiter);

    List<JobOffer> findByStatus(Status status);

    List<JobOffer> findByResumes_User_Id(Long userId);

    List<JobOffer> findByTitleContainsIgnoreCase(String title);
}
