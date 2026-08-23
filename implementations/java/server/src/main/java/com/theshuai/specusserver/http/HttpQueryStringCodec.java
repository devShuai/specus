package com.theshuai.specusserver.http;

/** Encodes the narrowly relaxed query characters before a request leaves the public server. */
final class HttpQueryStringCodec {
    private HttpQueryStringCodec() {
    }

    static String encodeForForwarding(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return rawQuery;
        }
        return rawQuery.replace("{", "%7B").replace("}", "%7D");
    }
}
