package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ManagementWorkbenchItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ManagementWorkbenchItemRepository
        extends JpaRepository<ManagementWorkbenchItem, ManagementWorkbenchItem.Key> {

    @Query("""
            select w from ManagementWorkbenchItem w
             where w.key.tenantId = :tenantId and w.key.username = :username
            """)
    List<ManagementWorkbenchItem> findByIdentity(@Param("tenantId") String tenantId,
                                                 @Param("username") String username);

    /** Every identity's reference to one object (the object is being deleted). */
    @Modifying
    @Query("""
            delete from ManagementWorkbenchItem w
             where w.key.kind = :kind and w.key.objectId = :objectId
            """)
    int deleteByObject(@Param("kind") String kind, @Param("objectId") long objectId);

    /**
     * Every identity's reference to a service carried by one client. Deleting a client leaves its
     * route, mapping and Peer service rows behind, so they are looked up by client id here.
     */
    @Modifying
    @Query("""
            delete from ManagementWorkbenchItem w
             where (w.key.kind = 'http-route' and w.key.objectId in
                        (select r.id from HttpRouteMapping r where r.clientId = :clientId))
                or (w.key.kind = 'tcp-mapping' and w.key.objectId in
                        (select m.id from SpecusMapping m where m.clientId = :clientId))
                or (w.key.kind = 'peer-service' and w.key.objectId in
                        (select s.id from PeerMeshSharedService s where s.clientId = :clientId))
            """)
    int deleteByClient(@Param("clientId") long clientId);

    /** Both lists of one identity (the account is being deleted). */
    @Modifying
    @Query("""
            delete from ManagementWorkbenchItem w
             where w.key.tenantId = :tenantId and w.key.username = :username
            """)
    int deleteByIdentity(@Param("tenantId") String tenantId, @Param("username") String username);

    /** The retention sweep: every identity's recent opens at or before the cutoff. */
    @Modifying
    @Query("""
            delete from ManagementWorkbenchItem w
             where w.key.listName = 'recent' and w.atMs <= :cutoffMs
            """)
    int deleteRecentsAtOrBefore(@Param("cutoffMs") long cutoffMs);
}
