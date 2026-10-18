package com.theshuai.specusserver.management.service;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.UnaryOperator;
import static org.junit.jupiter.api.Assertions.*;

/** Real Spring/JPA transactions and SQL commit/rollback, not fabricated synchronization flags.
 * This component proof uses immutable scalar payloads; real service DTO/copy/wire proof is separate. */
public final class PeerCatalogCacheAssertions {
    public static void verify(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        var tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var jdbc = context.getBean(JdbcTemplate.class);
        var executor = Executors.newFixedThreadPool(2);
        int scenarios = 0;
        try {
            for (boolean rollback : List.of(false, true)) {
                var cache = new PeerCatalogCache(4); var maps = indexes(cache);
                var key = key(11_000_001 + scenarios); long id = key.publisherClientId();
                seed(jdbc, id);
                tx.executeWithoutResult(status -> {
                    jdbc.update("update specus_client_account set enabled=false where id=?", id);
                    for (int i = 0; i < 4; i++) maps.get(i).put(key, "new-" + i);
                    assertValues(maps, key, "new-");
                    await(executor.submit(() -> assertValues(maps, key, null)));
                    if (rollback) status.setRollbackOnly();
                });
                assertValues(maps, key, rollback ? null : "new-");
                assertEquals(rollback, jdbc.queryForObject("select enabled from specus_client_account where id=?", Boolean.class, id));
                assertEquals(rollback ? 0 : 1, cache.retainedKeyCount()); scenarios++;
            }
            for (boolean rollback : List.of(false, true)) {
                var cache = new PeerCatalogCache(4); var maps = indexes(cache); var key = key(11_000_001 + scenarios);
                PeerCatalogCache.mutation(() -> { for (int i=0;i<4;i++) maps.get(i).put(key,"old-"+i); return null; });
                tx.executeWithoutResult(status -> {
                    for (var map : maps) map.remove(key);
                    assertValues(maps,key,null); await(executor.submit(() -> assertValues(maps,key,"old-")));
                    if (rollback) status.setRollbackOnly();
                });
                assertValues(maps,key,rollback?"old-":null);
                assertEquals(rollback?1:0,cache.retainedKeyCount()); scenarios++;
            }
            {
                var cache = new PeerCatalogCache(4); var map = cache.<String>index(0,UnaryOperator.identity());
                var first=key(11_000_001+scenarios); var second=key(first.publisherClientId()+100);
                tx.executeWithoutResult(status -> {
                    map.put(first,"outer");
                    var failure=await(executor.submit(() -> assertThrows(ResponseStatusException.class, () -> tx.executeWithoutResult(inner -> map.put(first,"forbidden")))));
                    assertEquals(503,failure.getStatusCode().value());
                    await(executor.submit(() -> tx.executeWithoutResult(inner -> map.put(second,"independent"))));
                    assertEquals("outer",map.get(first)); assertEquals("independent",map.get(second)); status.setRollbackOnly();
                });
                assertNull(map.get(first));assertEquals("independent",map.get(second));assertEquals(1,cache.retainedKeyCount());scenarios++;
            }
            for (boolean sameKey : List.of(false,true)) {
                var cache=new PeerCatalogCache(4);var map=cache.<String>index(0,UnaryOperator.identity());
                var first=key(11_000_001+scenarios);var second=key(first.publisherClientId()+100);map.put(first,"old");
                var inner=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));inner.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
                tx.executeWithoutResult(status -> {
                    assertEquals(1,jdbc.queryForObject("select 1",Integer.class));map.put(first,"outer");
                    if(sameKey) assertThrows(ResponseStatusException.class,()->inner.executeWithoutResult(nested->map.put(first,"illegal")));
                    else inner.executeWithoutResult(nested->{
                        assertEquals(1,jdbc.queryForObject("select 1",Integer.class));assertEquals("old",map.get(first));map.put(second,"inner");
                    });
                    assertEquals("outer",map.get(first));status.setRollbackOnly();
                });
                assertEquals("old",map.get(first));assertEquals(sameKey?null:"inner",map.get(second));scenarios++;
            }
            {
                var cache=new PeerCatalogCache(1);var map=cache.<String>index(0,UnaryOperator.identity());
                var first=key(11_000_001+scenarios);var second=key(first.publisherClientId()+100);
                tx.executeWithoutResult(status->{
                    map.put(first,"pending");assertEquals(1,cache.retainedKeyCount());
                    assertEquals(503,await(executor.submit(()->assertThrows(ResponseStatusException.class,()->tx.executeWithoutResult(other->map.put(second,"over budget"))))).getStatusCode().value());
                    status.setRollbackOnly();
                });
                assertEquals(0,cache.retainedKeyCount());tx.executeWithoutResult(status->map.put(second,"recovered"));assertEquals("recovered",map.get(second));scenarios++;
            }
            {
                var cache=new PeerCatalogCache(4);var maps=indexes(cache);var key=key(11_000_001+scenarios);
                tx.executeWithoutResult(status->{
                    TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
                        @Override public void afterCommit(){PeerCatalogCache.committedEffect(()->{
                            for(int i=0;i<4;i++)maps.get(i).put(key,"post-"+i);
                            PeerCatalogCache.committedEffect(()->{PeerCatalogCache.flushCommittedEffects();await(executor.submit(()->assertValues(maps,key,"post-")));});
                        });}
                    });
                    for(int i=0;i<4;i++)maps.get(i).put(key,"pre-"+i);
                });
                assertValues(maps,key,"post-");assertEquals(1,cache.retainedKeyCount());scenarios++;
            }
            {
                var cache=new PeerCatalogCache(4);var map=cache.<String>index(0,UnaryOperator.identity());var key=key(11_000_001+scenarios);seed(jdbc,key.publisherClientId());
                assertThrows(IllegalStateException.class,()->tx.executeWithoutResult(status->{
                    jdbc.update("update specus_client_account set enabled=false where id=?",key.publisherClientId());map.put(key,"pre");
                    TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
                        @Override public void afterCommit(){PeerCatalogCache.committedEffect(()->{map.put(key,"post");throw new IllegalStateException("intentional committed callback failure");});}
                    });
                }));
                assertFalse(jdbc.queryForObject("select enabled from specus_client_account where id=?",Boolean.class,key.publisherClientId()));assertEquals("post",map.get(key));
                tx.executeWithoutResult(status->map.put(key,"lease released"));assertEquals("lease released",map.get(key));scenarios++;
            }
            for (boolean beforeApply : List.of(true,false)) {
                var cache=new PeerCatalogCache(4);var map=cache.<String>index(0,UnaryOperator.identity());var key=key(11_000_001+scenarios);var other=key(key.publisherClientId()+100);seed(jdbc,key.publisherClientId());map.put(key,"old");
                var committed=new CountDownLatch(1);var release=new CountDownLatch(1);
                Future<?> owner=executor.submit(()->tx.executeWithoutResult(status->{
                    TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
                        @Override public int getOrder(){return beforeApply?org.springframework.core.Ordered.HIGHEST_PRECEDENCE:org.springframework.core.Ordered.LOWEST_PRECEDENCE;}
                        @Override public void afterCommit(){committed.countDown();try{assertTrue(release.await(5,TimeUnit.SECONDS));}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException(interrupted);}}
                    });
                    jdbc.update("update specus_client_account set enabled=false where id=?",key.publisherClientId());map.put(key,"first");
                }));
                try{
                    assertTrue(committed.await(5,TimeUnit.SECONDS));
                    assertFalse(jdbc.queryForObject("select enabled from specus_client_account where id=?",Boolean.class,key.publisherClientId()),"actual SQL commit already completed");
                    assertEquals(beforeApply?"old":"first",map.get(key));assertEquals(503,assertThrows(ResponseStatusException.class,()->tx.executeWithoutResult(status->map.put(key,"too early"))).getStatusCode().value());
                    tx.executeWithoutResult(status->map.put(other,"independent"));assertEquals("independent",map.get(other));
                }finally{release.countDown();await(owner);}
                assertEquals("first",map.get(key));tx.executeWithoutResult(status->map.put(key,"second"));assertEquals("second",map.get(key));scenarios++;
            }
            {
                var cache=new PeerCatalogCache(4);var map=cache.<String>index(0,UnaryOperator.identity());var key=key(11_000_001+scenarios);
                PeerCatalogCache.committedEffect(()->{
                    map.put(key,"effect");
                    assertThrows(IllegalStateException.class,()->tx.executeWithoutResult(status->{map.put(key(11_000_999),"must rollback");throw new IllegalStateException("real transaction inside effect");}));
                    assertNull(map.get(key(11_000_999)));
                });
                assertEquals("effect",map.get(key));assertNull(map.get(key(11_000_999)));scenarios++;
            }
            {
                var cache=new PeerCatalogCache(4);var map=cache.<String>index(0,UnaryOperator.identity());var key=key(11_000_001+scenarios);
                assertThrows(IllegalArgumentException.class,()->PeerCatalogCache.mutation(()->{map.put(key,"uncommitted memory mutation");throw new IllegalArgumentException("intentional memory rollback");}));
                assertNull(map.get(key));assertEquals(0,cache.retainedKeyCount());scenarios++;
            }
            System.out.println("[catalog-cache-proof] scenarios="+scenarios+" realJpaCommitRollback=PASS requiresNew=PASS perKeyAdmission=PASS lateCommitFences=PASS");
        }finally{executor.shutdownNow();assertTrue(executor.awaitTermination(5,TimeUnit.SECONDS));}
    }
    private static List<Map<PeerServiceDiscoveryService.CatalogKey,String>> indexes(PeerCatalogCache cache){
        List<Map<PeerServiceDiscoveryService.CatalogKey,String>> result=new ArrayList<>();for(int i=0;i<4;i++)result.add(cache.index(i,UnaryOperator.identity()));return result;
    }
    private static void assertValues(List<Map<PeerServiceDiscoveryService.CatalogKey,String>> maps,PeerServiceDiscoveryService.CatalogKey key,String prefix){for(int i=0;i<4;i++)assertEquals(prefix==null?null:prefix+i,maps.get(i).get(key));}
    private static PeerServiceDiscoveryService.CatalogKey key(long id){return new PeerServiceDiscoveryService.CatalogKey("default",id,id+40);}
    private static void seed(JdbcTemplate jdbc,long id){String now=Instant.now().toString();jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','catalog-cache',?,'fixture-only',true,30,?,?)",id,"catalog-cache-sql-"+id,now,now);}
    private static <T>T await(Future<T> future){try{return future.get(6,TimeUnit.SECONDS);}catch(ExecutionException failure){if(failure.getCause() instanceof AssertionError assertion)throw assertion;throw new IllegalStateException("catalog cache proof worker failed",failure.getCause());}catch(Exception failure){throw new IllegalStateException("catalog cache proof worker failed",failure);}}
}
