package com.auth.repository;

import com.auth.entity.OAuth2RegisteredClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClient, String> {

    Optional<OAuth2RegisteredClient> findByClientId(String clientId);

    @Query("SELECT c FROM OAuth2RegisteredClient c WHERE c.enabled = true")
    List<OAuth2RegisteredClient> findAllEnabledClients();

    boolean existsByClientId(String clientId);
    
    @Query("SELECT COUNT(c) FROM OAuth2RegisteredClient c WHERE c.enabled = true")
    long countEnabledClients();
}