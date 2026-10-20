#ifndef SPECUS_TRAFFIC_USAGE_H
#define SPECUS_TRAFFIC_USAGE_H

/*
 * Traffic usage counted in memory and written in batches, as Java TrafficUsageService does. The
 * forwarding threads only add to a counter per client and per resource, under one mutex; a flush
 * takes the counters and writes them, in one transaction, into the clients' days and the
 * resources' rows of the UTC date it runs on (st_storage_flush_traffic_usage). When the write
 * fails, the bytes go back into the counters for the next flush.
 */

/* Java recordTcpUpload/recordTcpDownload: the client's day, and tcp:<port> when listen_port > 0. */
void st_traffic_usage_record_tcp(const char *client_name, int listen_port, long long upload_bytes,
                                 long long download_bytes);
/* Java recordHttpUpload/recordHttpDownload: the client's day and http:<route>. */
void st_traffic_usage_record_http(const char *client_name, const char *route, long long upload_bytes,
                                  long long download_bytes);
/*
 * Java flush(), one at a time: 0 when everything counted so far is written (a client that no
 * longer exists is dropped, as Java drops it), -1 when the write failed and the counts were kept.
 * Nothing counted means nothing is opened.
 */
int st_traffic_usage_flush(const char *database_path);
/*
 * Flushes into database_path every SPECUS_TRAFFIC_FLUSH_INTERVAL_MS (Java
 * specus.traffic.flush-interval-ms, default 5000), the delay counted from the end of the last
 * flush. Nothing starts without a database. -1 when the thread cannot be started.
 */
int st_traffic_usage_start(const char *database_path);
/* Stops the periodic flush and flushes once more (Java flushBeforeShutdown). */
void st_traffic_usage_stop(void);

#endif
