package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshDevice;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;

@Transactional(propagation = Propagation.MANDATORY)
public class PeerMeshDeviceRepositoryCustomImpl implements PeerMeshDeviceRepositoryCustom {
    @PersistenceContext private EntityManager entities;
    @Override public Optional<PeerMeshDevice> lockCurrent(String tenant, Long client) {
        entities.createNativeQuery("update peer_mesh_device set enabled=enabled where tenant_id=?1 and client_id=?2")
                .setParameter(1, tenant).setParameter(2, client).executeUpdate();
        String lock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        var rows = entities.createNativeQuery("""
                select id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,public_key,
                       nat_type,nat_mapping_behavior,nat_filtering_behavior,nat_behavior_discovery,last_endpoint,
                       virtual_device_mode,virtual_device_name,virtual_device_status,virtual_device_error,
                       virtual_device_updated_at,enabled,last_seen_at,created_at,updated_at
                  from peer_mesh_device where tenant_id=?1 and client_id=?2
                """ + lock).setParameter(1, tenant).setParameter(2, client).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        PeerMeshDevice device = new PeerMeshDevice();
        device.setId(((Number) row[0]).longValue()); device.setTenantId((String) row[1]);
        device.setOwnerUsername((String) row[2]); device.setClientId(((Number) row[3]).longValue());
        device.setClientName((String) row[4]); device.setVirtualIp((String) row[5]); device.setCidr((String) row[6]);
        device.setPublicKey((String) row[7]); device.setNatType((String) row[8]);
        device.setNatMappingBehavior((String) row[9]); device.setNatFilteringBehavior((String) row[10]);
        device.setNatBehaviorDiscovery((String) row[11]); device.setLastEndpoint((String) row[12]);
        device.setVirtualDeviceMode((String) row[13]); device.setVirtualDeviceName((String) row[14]);
        device.setVirtualDeviceStatus((String) row[15]); device.setVirtualDeviceError((String) row[16]);
        device.setVirtualDeviceUpdatedAt((String) row[17]);
        device.setEnabled(row[18] instanceof Boolean enabled ? enabled : ((Number) row[18]).intValue() != 0);
        device.setLastSeenAt((String) row[19]); device.setCreatedAt((String) row[20]); device.setUpdatedAt((String) row[21]);
        return tenant.equals(device.getTenantId()) ? Optional.of(device) : Optional.empty();
    }
}
