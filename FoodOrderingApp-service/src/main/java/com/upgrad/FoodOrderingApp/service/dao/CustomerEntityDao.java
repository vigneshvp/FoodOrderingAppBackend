package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

@Repository
public class CustomerEntityDao {


    @PersistenceContext
    private EntityManager entityManager;

    public CustomerEntity createCustomer(CustomerEntity CustomerEntity) {
        entityManager.persist(CustomerEntity);
        return CustomerEntity;
    }

    public CustomerEntity getCustomerByUuid(final String uuid) {
        try {
            return entityManager.createNamedQuery("customerByUuid", CustomerEntity.class)
                    .setParameter("uuid", uuid)
                    .getSingleResult();
        } catch (final NoResultException nre) {
            return null;
        }
    }

    public CustomerEntity getCustomerByEmail(final String email) {
        try {
            return entityManager.createNamedQuery("customerByEmail", CustomerEntity.class)
                    .setParameter("email", email).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }


    public CustomerAuthEntity createAuthToken(final CustomerAuthEntity CustomerAuthEntity) {
        entityManager.persist(CustomerAuthEntity);
        return CustomerAuthEntity;
    }

    public void updateCustomer(final CustomerEntity updatedCustomerEntity) {
        entityManager.merge(updatedCustomerEntity);
    }

    public void updateCustomerAuthEntity(final CustomerAuthEntity updatedCustomerAuthEntity) {
        entityManager.merge(updatedCustomerAuthEntity);
    }


    public CustomerAuthEntity getCustomerAuthToken(final String accessToken) {
        try {
            return entityManager
                    .createNamedQuery("customerAuthByAccessToken", CustomerAuthEntity.class)
                    .setParameter("accessToken", accessToken).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    @OnDelete(action = OnDeleteAction.CASCADE)
    @Transactional
    public void deleteCustomer(final CustomerEntity CustomerEntity) {
        entityManager.remove(CustomerEntity);
    }

}
