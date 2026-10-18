/* Compile the actual private queue implementation, without any production-only testing hooks. */
#define main specus_control_server_main
#include "../src/main.c"
#undef main

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL queue line %d: %s\n", __LINE__, #c); return 1; } } while (0)
static void initialize(specus_session *session)
{
    memset(session, 0, sizeof(*session));
    atomic_init(&session->control_cancelled, 0);
    pthread_cond_init(&session->control_work_cond, NULL);
}
static st_message_response packet(size_t bytes)
{
    st_message_response message = {0};
    message.message = malloc(bytes + 1);
    if (message.message != NULL) { memset(message.message, 'x', bytes); message.message[bytes] = '\0'; }
    return message;
}
int main(void)
{
    specus_session session;
    initialize(&session);
    for (size_t i = 0; i < ST_CONTROL_WORK_ITEMS; ++i) {
        st_message_response message = packet(1);
        CHECK(message.message && control_message_enqueue(&session, &message) == 0 && message.message == NULL);
    }
    CHECK(session.control_work_count == ST_CONTROL_WORK_ITEMS && session.control_work_queued);
    st_message_response overflow = packet(1);
    CHECK(control_message_enqueue(&session, &overflow) == -1 && overflow.message != NULL);
    pthread_mutex_lock(&control_queue_lock);
    control_work_item *in_flight = session.control_work_head;
    session.control_work_head = in_flight->next;
    pthread_mutex_unlock(&control_queue_lock);
    CHECK(control_message_enqueue(&session, &overflow) == -1); /* Executing work still charges its slot. */
    pthread_mutex_lock(&control_queue_lock);
    control_work_free_locked(&session, in_flight);
    pthread_mutex_unlock(&control_queue_lock);
    CHECK(control_message_enqueue(&session, &overflow) == 0 && overflow.message == NULL);
    control_worker_stop(&session);
    CHECK(session.control_work_count == 0 && session.control_work_bytes == 0 && control_work_bytes == 0
        && control_ready_head == NULL && control_ready_tail == NULL);
    overflow = packet(1);
    CHECK(control_message_enqueue(&session, &overflow) == -1 && overflow.message != NULL);
    st_message_response_free(&overflow);
    pthread_cond_destroy(&session.control_work_cond);

    initialize(&session);
    st_message_response large = packet(ST_MAX_FRAME_SIZE - 16);
    CHECK(large.message && control_message_enqueue(&session, &large) == 0); /* A legal max-sized frame fits. */
    large = packet(ST_MAX_FRAME_SIZE - 16);
    CHECK(large.message && control_message_enqueue(&session, &large) == -1); /* Byte budget, not slot budget. */
    st_message_response_free(&large);
    control_worker_stop(&session);
    CHECK(control_work_bytes == 0);
    pthread_cond_destroy(&session.control_work_cond);

    initialize(&session);
    control_work_bytes = ST_CONTROL_GLOBAL_WORK_BYTES - 1;
    overflow = packet(1);
    CHECK(control_message_enqueue(&session, &overflow) == -1 && session.control_work_bytes == 0);
    st_message_response_free(&overflow);
    control_work_bytes = 0;
    /* Stopped sources still persist an already accepted login audit before teardown can free it. */
    CHECK(control_worker_start(&session) == 0 && control_pool_count == ST_CONTROL_POOL_SIZE);
    for (int i = 0; i < 64; ++i) CHECK(control_worker_start(&session) == 0 && control_pool_count == ST_CONTROL_POOL_SIZE);
    control_login_audit_enqueue(&session, 0);
    control_worker_stop(&session);
    CHECK(!session.login_audit_pending && !session.control_work_busy && !session.control_work_queued);
    control_pool_stop();
    pthread_cond_destroy(&session.control_work_cond);
    puts("PASS queue ownership, in-flight slot/byte budgets, global admission, detach reclamation, fixed pool and audit drain");
    return 0;
}
