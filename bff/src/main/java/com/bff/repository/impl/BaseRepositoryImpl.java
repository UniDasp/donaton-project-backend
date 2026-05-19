package com.bff.repository.impl;

import com.bff.repository.BaseRepository;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import java.io.Serializable;
import java.util.List;
import java.util.Optional;


@Transactional(readOnly = true)
public abstract class BaseRepositoryImpl<T, ID extends Serializable> 
        extends SimpleJpaRepository<T, ID> 
        implements BaseRepository<T, ID> {

    private final EntityManager entityManager;

   
    public BaseRepositoryImpl(
            JpaEntityInformation<T, ID> entityInformation,
            EntityManager entityManager) {
        super(entityInformation, entityManager);
        this.entityManager = entityManager;
    }

   
    @Override
    @Transactional
    public T update(T entity) {
        return entityManager.merge(entity);
    }

   
    @Override
    @Transactional
    public T save(T entity) {
        super.save(entity);
        return entity;
    }

    @Override
    @Transactional
    public List<T> saveAll(Iterable<T> entities) {
        return super.saveAll(entities);
    }

   
    @Override
    public Optional<T> findById(ID id) {
        return super.findById(id);
    }

    @Override
    public List<T> findAll() {
        return super.findAll();
    }

    @Override
    @Transactional
    public void deleteById(ID id) {
        super.deleteById(id);
    }

    @Override
    public boolean existsById(ID id) {
        return super.existsById(id);
    }

   
    @Override
    public long count() {
        return super.count();
    }

  
    protected EntityManager getEntityManager() {
        return entityManager;
    }
}
