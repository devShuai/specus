package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.util.*;

/** A nonlocking, single-statement MVCC read model. It bypasses JPA/L1 and caller-owned entity
 * fields, not an enclosing transaction's explicit repeatable-read snapshot. Do not use this
 * informational view as a replacement for current locking routing/grant authorization. */
@Repository
public class PeerReadSnapshotRepository {
    @PersistenceContext private EntityManager entities;
    public record Peer(long id,String tenant,String owner,String name,boolean enabled,String deviceTenant,
                       boolean deviceEnabled,String virtualIp,String publicKey) {
        public boolean available(String expectedTenant){return enabled&&deviceEnabled&&expectedTenant.equals(tenant)&&expectedTenant.equals(deviceTenant);}
    }
    public record Acl(String tenant,boolean allowed,String direction) {
        private boolean permits(String expectedTenant,String direction){return allowed&&expectedTenant.equals(tenant)&&(direction.equals(this.direction)||"BOTH".equals(this.direction));}
    }
    public record Edge(Peer source,Peer target,Acl forward,Acl reverse) {
        public boolean outgoing(String tenant){return permitted(tenant,false);}
        public boolean incoming(String tenant){return permitted(tenant,true);}
        private boolean permitted(String tenant,boolean incoming){
            if(!source.available(tenant)||!target.available(tenant))return false;
            if(owner(source.owner()).equals(owner(target.owner())))return true;
            return incoming ? forward.permits(tenant,"INBOUND")||reverse.permits(tenant,"OUTBOUND")
                    :forward.permits(tenant,"OUTBOUND")||reverse.permits(tenant,"INBOUND");
        }
    }
    public record Capabilities(long sessionId,String tenant,long clientId,String status,boolean send,boolean receive,
                               boolean attachments,boolean media,long maxBytes,int discoveryVersion,String applications) {}
    public record Snapshot(String tenant,Peer source,List<Edge> edges,Map<Long,List<Capabilities>> sessions,List<PeerMeshSharedService> definitions){
        public static Snapshot empty(String tenant){return new Snapshot(tenant,null,List.of(),Map.of(),List.of());}
        public Optional<Edge> edge(long target){return edges.stream().filter(row->row.target().id()==target).findFirst();}
    }
    public static String owner(String value){return StringUtils.hasText(value)?value.trim():"admin";}
    private static final String PEERS="""
            a.id,a.tenant_id,a.owner_username,a.client_name,a.enabled,ad.tenant_id,ad.enabled,ad.virtual_ip,ad.public_key,
            b.id,b.tenant_id,b.owner_username,b.client_name,b.enabled,bd.tenant_id,bd.enabled,bd.virtual_ip,bd.public_key,
            f.tenant_id,f.allowed,f.direction,r.tenant_id,r.allowed,r.direction,
            cs.id,cs.tenant_id,cs.client_id,cs.status,cs.message_send_capable,cs.message_receive_capable,
            cs.message_attachments_capable,cs.message_media_preview_capable,cs.message_max_attachment_bytes,
            cs.peer_service_discovery_version,cs.peer_service_applications
            """;
    private static final String DEFINITIONS="""
            d.id,d.tenant_id,d.client_id,p.client_name,d.service_id,d.name,d.description,d.transport,d.application,
            d.target_host,d.target_port,d.published_port,d.path,d.enabled,d.visibility,d.allowed_client_ids,d.created_at,d.updated_at
            """;
    @Transactional(readOnly=true)
    public Snapshot read(String tenant,long source){
        return read(tenant,source,null,true);
    }

    /** Pair checks must not grow with the tenant's device roster or service definitions. */
    @Transactional(readOnly=true)
    public Snapshot readPair(String tenant,long source,long target){
        return read(tenant,source,target,false);
    }

    private Snapshot read(String tenant,long source,Long target,boolean definitionsIncluded){
        // UNION avoids a query per definition or repeating a definition for every peer. Both
        // branches still share one database statement/snapshot (also PostgreSQL READ COMMITTED).
        String sql="/* peer-read-snapshot */ select 'P' as c0,"+columns(PEERS,1)+","+columns(nulls(18),36)+"""
                 from specus_client_account a
                 left join peer_mesh_device ad on ad.client_id=a.id and ad.tenant_id=a.tenant_id
                 join specus_client_account b on b.tenant_id=a.tenant_id
                 left join peer_mesh_device bd on bd.client_id=b.id and bd.tenant_id=b.tenant_id
                 left join peer_mesh_acl f on f.source_client_id=a.id and f.target_client_id=b.id and f.tenant_id=a.tenant_id
                 left join peer_mesh_acl r on r.source_client_id=b.id and r.target_client_id=a.id and r.tenant_id=a.tenant_id
                 left join specus_client_session cs on cs.client_id=b.id and cs.tenant_id=b.tenant_id and cs.status='NETTY_ONLINE'
                 where a.id=?1 and a.tenant_id=?2
                """+(target==null?"":" and b.id=?3 ")+"""
                 union all select 'D',
                """+nulls(35)+","+DEFINITIONS+"""
                 from peer_mesh_shared_service d join specus_client_account p on p.id=d.client_id and p.tenant_id=d.tenant_id
                 where d.client_id=?1 and d.tenant_id=?2
                """+(definitionsIncluded?"":" and 1=0 ");
        // SQLite infers NULL-first UNION columns from the first row as numeric; never let
        // Hibernate guess extraction types (e.g. tenant names as BigDecimal). These explicit
        // scalars also normalize CHAR and boolean representations across all four providers.
        var query=entities.createNativeQuery(sql).unwrap(org.hibernate.query.NativeQuery.class);
        Set<Integer> numeric=Set.of(1,10,25,27,33,34,36,38,46,47);
        Set<Integer> flags=Set.of(5,7,14,16,20,23,29,30,31,32,49);
        for(int i=0;i<54;i++){
            if(numeric.contains(i))query.addScalar("c"+i,Long.class);
            else if(flags.contains(i))query.addScalar("c"+i,Boolean.class);
            else query.addScalar("c"+i,String.class);
        }
        query.setParameter(1,source).setParameter(2,tenant);
        if(target!=null)query.setParameter(3,target);
        List<?> rows=query.getResultList();
        Peer anchor=null;Map<Long,Edge> peers=new LinkedHashMap<>();Map<Long,List<Capabilities>> sessions=new LinkedHashMap<>();List<PeerMeshSharedService> definitions=new ArrayList<>();
        for(Object item:rows){
            Object[] row=(Object[])item;
            // CHAR(1) discriminators are Character on some Hibernate dialects, String on others.
            if("D".equals(String.valueOf(row[0]))){if(tenant.equals(row[37]))definitions.add(definition(row));continue;}
            Peer a=peer(row,1),b=peer(row,10);anchor=a;
            if(!tenant.equals(a.tenant())||!tenant.equals(b.tenant()))continue;
            peers.putIfAbsent(b.id(),new Edge(a,b,new Acl((String)row[19],bool(row[20]),(String)row[21]),new Acl((String)row[22],bool(row[23]),(String)row[24])));
            if(row[25]!=null){
                var caps=new Capabilities(number(row[25]),(String)row[26],number(row[27]),(String)row[28],bool(row[29]),bool(row[30]),bool(row[31]),bool(row[32]),number(row[33]),(int)number(row[34]),(String)row[35]);
                if(tenant.equals(caps.tenant())&&caps.clientId()==b.id()&&"NETTY_ONLINE".equals(caps.status()))sessions.computeIfAbsent(b.id(),ignored->new ArrayList<>()).add(caps);
            }
        }
        if(anchor==null||!tenant.equals(anchor.tenant()))return Snapshot.empty(tenant);
        Map<Long,List<Capabilities>> immutable=new LinkedHashMap<>();sessions.forEach((id,caps)->immutable.put(id,List.copyOf(caps)));
        return new Snapshot(tenant,anchor,List.copyOf(peers.values()),Collections.unmodifiableMap(immutable),List.copyOf(definitions));
    }
    private static String nulls(int count){return String.join(",",Collections.nCopies(count,"null"));}
    private static String columns(String expressions,int offset){
        String[] parts=expressions.trim().split(",");
        for(int i=0;i<parts.length;i++)parts[i]=parts[i].trim()+" as c"+(i+offset);
        return String.join(",",parts);
    }
    private static long number(Object value){return value==null?0:((Number)value).longValue();}
    private static boolean bool(Object value){return value instanceof Boolean b?b:value instanceof Number n&&n.intValue()!=0;}
    private static Peer peer(Object[] row,int offset){return new Peer(number(row[offset]),(String)row[offset+1],(String)row[offset+2],(String)row[offset+3],bool(row[offset+4]),(String)row[offset+5],bool(row[offset+6]),(String)row[offset+7],(String)row[offset+8]);}
    private static PeerMeshSharedService definition(Object[] row){
        var value=new PeerMeshSharedService();value.setId(number(row[36]));value.setTenantId((String)row[37]);value.setClientId(number(row[38]));value.setClientName((String)row[39]);
        value.setServiceId((String)row[40]);value.setName((String)row[41]);value.setDescription((String)row[42]);value.setTransport((String)row[43]);value.setApplication((String)row[44]);
        value.setTargetHost((String)row[45]);value.setTargetPort((int)number(row[46]));value.setPublishedPort((int)number(row[47]));value.setPath((String)row[48]);value.setEnabled(bool(row[49]));
        value.setVisibility((String)row[50]);value.setAllowedClientIds((String)row[51]);value.setCreatedAt((String)row[52]);value.setUpdatedAt((String)row[53]);return value;
    }
}
