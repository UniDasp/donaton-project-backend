package com.bff.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.List;
import java.util.Optional;


@NoRepositoryBean
public interface BaseRepository<T, ID> extends JpaRepository<T, ID> {

    
    Optional<T> findById(ID id);

    List<T> findAll();

    
    T save(T entity);

  
    List<T> saveAll(Iterable<T> entities);

   
    T update(T entity);

    
    void deleteById(ID id);

   
    boolean existsById(ID id);

   
    long count();
}
