using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Management;

public sealed class ElasticsearchTrafficDetailClient
{
    private const int TrimBatchSize = 500;
    private const int MaxTrimBatches = 20;
    private static readonly TimeSpan TrimInterval = TimeSpan.FromMinutes(1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly ElasticsearchOptions _options;
    private readonly HttpClient _http;
    private readonly Uri? _endpoint;
    private readonly SemaphoreSlim _indexLock = new(1, 1);
    private long _sequence;
    private long _httpLastTrimTicks;
    private long _tcpLastTrimTicks;
    private bool _httpIndexReady;
    private bool _tcpIndexReady;

    public ElasticsearchTrafficDetailClient(IOptions<ElasticsearchOptions> options, IHttpClientFactory factory)
    {
        _options = options.Value;
        _http = factory.CreateClient(nameof(ElasticsearchTrafficDetailClient));
        _endpoint = _options.EndpointUris().FirstOrDefault();
    }

    public bool IsEnabled => _options.IsConfigured && _endpoint is not null;

    public async Task SaveHttpAsync(HttpTrafficExchange exchange, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            return;
        }
        await EnsureHttpIndexAsync(cancellationToken).ConfigureAwait(false);
        var id = DocumentId(exchange.Id);
        var document = HttpDocument.FromEntity(exchange, id);
        await PutDocumentAsync(_options.HttpIndex, id.ToString(CultureInfo.InvariantCulture), document, cancellationToken)
            .ConfigureAwait(false);
        await TrimIfNecessaryAsync(_options.HttpIndex, _options.HttpMaxStoreBytes, httpIndex: true, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task SaveTcpAsync(TcpTrafficFrame frame, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            return;
        }
        await EnsureTcpIndexAsync(cancellationToken).ConfigureAwait(false);
        var id = DocumentId(frame.Id);
        var document = TcpDocument.FromEntity(frame, id);
        await PutDocumentAsync(_options.TcpIndex, id.ToString(CultureInfo.InvariantCulture), document, cancellationToken)
            .ConfigureAwait(false);
        await TrimIfNecessaryAsync(_options.TcpIndex, _options.TcpMaxStoreBytes, httpIndex: false, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<TrafficDetailPage<HttpTrafficExchangeView>> ListHttpAsync(
        ManagementContext context,
        IReadOnlyList<long> visibleClientIds,
        long? clientId,
        string? route,
        string? responseBodyType,
        string? field,
        string? q,
        int page,
        int size,
        CancellationToken cancellationToken)
    {
        await EnsureHttpIndexAsync(cancellationToken).ConfigureAwait(false);
        var query = new Dictionary<string, object?>
        {
            ["query"] = BuildHttpQuery(context, visibleClientIds, clientId, route, responseBodyType, field, q),
            ["from"] = page * size,
            ["size"] = size,
            ["sort"] = new object[] { new Dictionary<string, object?> { ["id"] = new { order = "desc" } } },
            ["_source"] = new
            {
                excludes = new[]
                {
                    "requestHeaders",
                    "responseHeaders",
                    "requestPreviewHex",
                    "requestPreviewText",
                    "responsePreviewHex",
                    "responsePreviewText",
                },
            },
        };
        var response = await RequestJsonAsync<EsSearchResponse<HttpDocument>>(
                HttpMethod.Post, $"/{Escape(_options.HttpIndex)}/_search", query, cancellationToken)
            .ConfigureAwait(false);
        var items = response.Hits.Hits.Select(hit => hit.Source.ToView(includeDetail: false)).ToList();
        return new TrafficDetailPage<HttpTrafficExchangeView>(
            items,
            response.Hits.Total.Value,
            page,
            size,
            TotalPages(response.Hits.Total.Value, size));
    }

    public async Task<HttpTrafficExchangeView?> GetHttpExchangeAsync(
        ManagementContext context,
        IReadOnlyList<long> visibleClientIds,
        long id,
        CancellationToken cancellationToken)
    {
        if (visibleClientIds.Count == 0)
        {
            return null;
        }
        await EnsureHttpIndexAsync(cancellationToken).ConfigureAwait(false);
        var query = BuildHttpQuery(
            context,
            visibleClientIds,
            clientId: null,
            route: null,
            responseBodyType: null,
            field: null,
            q: null);
        var filters = (List<object>)((Dictionary<string, object?>)query["bool"]!)["filter"]!;
        filters.Add(Term("id", id));
        var request = new Dictionary<string, object?>
        {
            ["query"] = query,
            ["size"] = 1,
        };
        var response = await RequestJsonAsync<EsSearchResponse<HttpDocument>>(
                HttpMethod.Post, $"/{Escape(_options.HttpIndex)}/_search", request, cancellationToken)
            .ConfigureAwait(false);
        return response.Hits.Hits.FirstOrDefault()?.Source.ToView(includeDetail: true);
    }

    public async Task<TrafficDetailPage<TcpTrafficFrameView>> ListTcpAsync(
        ManagementContext context,
        IReadOnlyList<long> visibleClientIds,
        long? clientId,
        int? listenPort,
        int page,
        int size,
        CancellationToken cancellationToken)
    {
        await EnsureTcpIndexAsync(cancellationToken).ConfigureAwait(false);
        var query = new Dictionary<string, object?>
        {
            ["query"] = BuildTcpQuery(context, visibleClientIds, clientId, listenPort, null),
            ["from"] = page * size,
            ["size"] = size,
            ["sort"] = new object[] { new Dictionary<string, object?> { ["id"] = new { order = "desc" } } },
        };
        var response = await RequestJsonAsync<EsSearchResponse<TcpDocument>>(
                HttpMethod.Post, $"/{Escape(_options.TcpIndex)}/_search", query, cancellationToken)
            .ConfigureAwait(false);
        var items = response.Hits.Hits.Select(hit => hit.Source.ToView(includePayload: false)).ToList();
        return new TrafficDetailPage<TcpTrafficFrameView>(
            items,
            response.Hits.Total.Value,
            page,
            size,
            TotalPages(response.Hits.Total.Value, size));
    }

    public async Task<TcpTrafficFrameView?> GetTcpFrameAsync(
        ManagementContext context,
        IReadOnlyList<long> visibleClientIds,
        long id,
        CancellationToken cancellationToken)
    {
        if (visibleClientIds.Count == 0)
        {
            return null;
        }
        await EnsureTcpIndexAsync(cancellationToken).ConfigureAwait(false);
        var query = BuildTcpQuery(context, visibleClientIds, clientId: null, listenPort: null, channelId: null);
        var filters = (List<object>)((Dictionary<string, object?>)query["bool"]!)["filter"]!;
        filters.Add(Term("id", id));
        var request = new Dictionary<string, object?>
        {
            ["query"] = query,
            ["size"] = 1,
        };
        var response = await RequestJsonAsync<EsSearchResponse<TcpDocument>>(
                HttpMethod.Post, $"/{Escape(_options.TcpIndex)}/_search", request, cancellationToken)
            .ConfigureAwait(false);
        return response.Hits.Hits.FirstOrDefault()?.Source.ToView(includePayload: true);
    }

    public async Task<IReadOnlyList<TcpTrafficFrameView>> ListTcpStreamAsync(
        ManagementContext context,
        IReadOnlyList<long> visibleClientIds,
        string channelId,
        int limit,
        CancellationToken cancellationToken)
    {
        if (visibleClientIds.Count == 0 || string.IsNullOrWhiteSpace(channelId))
        {
            return [];
        }
        await EnsureTcpIndexAsync(cancellationToken).ConfigureAwait(false);
        var request = new Dictionary<string, object?>
        {
            ["query"] = BuildTcpQuery(context, visibleClientIds, clientId: null, listenPort: null, channelId.Trim()),
            ["size"] = Math.Clamp(limit, 1, 1000),
            ["sort"] = new object[] { new Dictionary<string, object?> { ["id"] = new { order = "asc" } } },
        };
        var response = await RequestJsonAsync<EsSearchResponse<TcpDocument>>(
                HttpMethod.Post, $"/{Escape(_options.TcpIndex)}/_search", request, cancellationToken)
            .ConfigureAwait(false);
        return response.Hits.Hits.Select(hit => hit.Source.ToView(includePayload: true)).ToList();
    }

    private async Task EnsureHttpIndexAsync(CancellationToken cancellationToken) =>
        await EnsureIndexAsync(_options.HttpIndex, HttpMapping(), () => _httpIndexReady, value => _httpIndexReady = value,
            cancellationToken).ConfigureAwait(false);

    private async Task EnsureTcpIndexAsync(CancellationToken cancellationToken) =>
        await EnsureIndexAsync(_options.TcpIndex, TcpMapping(), () => _tcpIndexReady, value => _tcpIndexReady = value,
            cancellationToken).ConfigureAwait(false);

    private async Task EnsureIndexAsync(string index, object mapping, Func<bool> getReady, Action<bool> setReady,
        CancellationToken cancellationToken)
    {
        if (getReady())
        {
            return;
        }
        await _indexLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (getReady())
            {
                return;
            }
            var head = await SendAsync(HttpMethod.Head, $"/{Escape(index)}", content: null, cancellationToken)
                .ConfigureAwait(false);
            if (head.StatusCode == HttpStatusCode.OK)
            {
                setReady(true);
                return;
            }
            if (head.StatusCode != HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException($"Elasticsearch inspect index {index} returned {(int)head.StatusCode}");
            }
            await RequestJsonAsync<object>(HttpMethod.Put, $"/{Escape(index)}", mapping, cancellationToken)
                .ConfigureAwait(false);
            setReady(true);
        }
        finally
        {
            _indexLock.Release();
        }
    }

    private async Task PutDocumentAsync(string index, string id, object document, CancellationToken cancellationToken) =>
        await RequestJsonAsync<object>(HttpMethod.Put, $"/{Escape(index)}/_doc/{Escape(id)}",
                document, cancellationToken)
            .ConfigureAwait(false);

    private async Task<T> RequestJsonAsync<T>(HttpMethod method, string path, object? payload,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync(method, path, payload, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Elasticsearch {method} {path} returned {(int)response.StatusCode}: {body}");
        }
        if (typeof(T) == typeof(object) || string.IsNullOrWhiteSpace(body))
        {
            return default!;
        }
        return JsonSerializer.Deserialize<T>(body, JsonOptions)
               ?? throw new InvalidOperationException($"Elasticsearch {method} {path} returned an empty JSON body");
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? content,
        CancellationToken cancellationToken)
    {
        if (_endpoint is null)
        {
            throw new InvalidOperationException("Elasticsearch endpoint is not configured");
        }
        var request = new HttpRequestMessage(method, new Uri(_endpoint, path));
        if (content is not null)
        {
            request.Content = new StringContent(JsonSerializer.Serialize(content, JsonOptions), Encoding.UTF8,
                "application/json");
        }
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("ApiKey", _options.ApiKey.Trim());
        }
        else if (!string.IsNullOrWhiteSpace(_options.Username) || !string.IsNullOrWhiteSpace(_options.Password))
        {
            var credential = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credential);
        }
        return await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task TrimIfNecessaryAsync(string index, long maxBytes, bool httpIndex,
        CancellationToken cancellationToken)
    {
        if (maxBytes <= 0)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow.UtcTicks;
        var last = httpIndex ? Interlocked.Read(ref _httpLastTrimTicks) : Interlocked.Read(ref _tcpLastTrimTicks);
        if (last != 0 && new TimeSpan(now - last) < TrimInterval)
        {
            return;
        }
        var exchanged = httpIndex
            ? Interlocked.CompareExchange(ref _httpLastTrimTicks, now, last)
            : Interlocked.CompareExchange(ref _tcpLastTrimTicks, now, last);
        if (exchanged != last)
        {
            return;
        }
        var storeBytes = await CurrentStoreBytesAsync(index, cancellationToken).ConfigureAwait(false);
        for (var batch = 0; storeBytes > maxBytes && batch < MaxTrimBatches; batch++)
        {
            var ids = await OldestDocumentIdsAsync(index, cancellationToken).ConfigureAwait(false);
            if (ids.Count == 0)
            {
                return;
            }
            await BulkDeleteAsync(index, ids, cancellationToken).ConfigureAwait(false);
            storeBytes = await CurrentStoreBytesAsync(index, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<long> CurrentStoreBytesAsync(string index, CancellationToken cancellationToken)
    {
        var response = await RequestJsonAsync<EsStatsResponse>(
                HttpMethod.Get, $"/{Escape(index)}/_stats/store", payload: null, cancellationToken)
            .ConfigureAwait(false);
        if (!response.Indices.TryGetValue(index, out var stats))
        {
            return 0;
        }
        return stats.Total.Store.TotalDataSetSizeInBytes > 0
            ? stats.Total.Store.TotalDataSetSizeInBytes
            : stats.Total.Store.SizeInBytes;
    }

    private async Task<IReadOnlyList<string>> OldestDocumentIdsAsync(string index, CancellationToken cancellationToken)
    {
        var request = new Dictionary<string, object?>
        {
            ["query"] = new Dictionary<string, object?> { ["match_all"] = new Dictionary<string, object?>() },
            ["size"] = TrimBatchSize,
            ["sort"] = new object[] { new Dictionary<string, object?> { ["id"] = new { order = "asc" } } },
        };
        var response = await RequestJsonAsync<EsSearchResponse<Dictionary<string, object?>>>(
                HttpMethod.Post, $"/{Escape(index)}/_search", request, cancellationToken)
            .ConfigureAwait(false);
        return response.Hits.Hits.Select(hit => hit.Id).Where(id => !string.IsNullOrWhiteSpace(id)).ToList();
    }

    private async Task BulkDeleteAsync(string index, IReadOnlyList<string> ids, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        foreach (var id in ids)
        {
            builder.Append(JsonSerializer.Serialize(new
            {
                delete = new Dictionary<string, string> { ["_index"] = index, ["_id"] = id },
            }, JsonOptions));
            builder.Append('\n');
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_endpoint!, "/_bulk"))
        {
            Content = new StringContent(builder.ToString(), Encoding.UTF8, "application/x-ndjson"),
        };
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("ApiKey", _options.ApiKey.Trim());
        }
        else if (!string.IsNullOrWhiteSpace(_options.Username) || !string.IsNullOrWhiteSpace(_options.Password))
        {
            var credential = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credential);
        }
        using var actual = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!actual.IsSuccessStatusCode)
        {
            var body = await actual.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException($"Elasticsearch bulk delete returned {(int)actual.StatusCode}: {body}");
        }
    }

    private Dictionary<string, object?> BuildHttpQuery(ManagementContext context, IReadOnlyList<long> visibleClientIds,
        long? clientId, string? route, string? responseBodyType, string? field, string? q)
    {
        var filters = new List<object> { Term("tenantId", context.TenantId) };
        if (clientId is not null)
        {
            filters.Add(Term("clientId", clientId.Value));
        }
        else if (visibleClientIds.Count > 0)
        {
            filters.Add(Terms("clientId", visibleClientIds));
        }
        if (!string.IsNullOrWhiteSpace(route))
        {
            filters.Add(Term("route", route.Trim()));
        }
        if (!string.IsNullOrWhiteSpace(responseBodyType))
        {
            filters.Add(ResponseBodyTypeQuery(responseBodyType.Trim().ToLowerInvariant()));
        }
        var must = new List<object>();
        foreach (var token in (q ?? string.Empty).Split(' ', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            must.Add(HttpTokenQuery(field, token));
        }
        return new Dictionary<string, object?> { ["bool"] = new Dictionary<string, object?> { ["filter"] = filters, ["must"] = must } };
    }

    private Dictionary<string, object?> BuildTcpQuery(ManagementContext context, IReadOnlyList<long> visibleClientIds,
        long? clientId, int? listenPort, string? channelId)
    {
        var filters = new List<object> { Term("tenantId", context.TenantId) };
        if (clientId is not null)
        {
            filters.Add(Term("clientId", clientId.Value));
        }
        else if (visibleClientIds.Count > 0)
        {
            filters.Add(Terms("clientId", visibleClientIds));
        }
        if (listenPort is not null)
        {
            filters.Add(Term("listenPort", listenPort.Value));
        }
        if (!string.IsNullOrWhiteSpace(channelId))
        {
            filters.Add(Term("channelId", channelId.Trim()));
        }
        return new Dictionary<string, object?> { ["bool"] = new Dictionary<string, object?> { ["filter"] = filters } };
    }

    private static object HttpTokenQuery(string? field, string token)
    {
        var normalizedField = NormalizeHttpSearchField(field);
        var normalizedToken = token.Trim().ToLowerInvariant();
        return normalizedField switch
        {
            "id" => long.TryParse(normalizedToken, out var id) ? Term("id", id) : NoMatch(),
            "method" => Term("method", normalizedToken.ToUpperInvariant()),
            "status" or "statuscode" =>
                int.TryParse(normalizedToken, out var status) ? Term("statusCode", status) : NoMatch(),
            "route" => Any(Wildcard("route", normalizedToken)),
            "path" or "relativepath" =>
                Any(MultiMatch(normalizedToken, "relativePath", "rawQuery"),
                    Wildcard("relativePath", normalizedToken), Wildcard("rawQuery", normalizedToken)),
            "query" or "rawquery" =>
                Any(MultiMatch(normalizedToken, "rawQuery"), Wildcard("rawQuery", normalizedToken)),
            "client" or "clientid" or "clientname" => long.TryParse(normalizedToken, out var clientId)
                ? Any(Wildcard("clientName", normalizedToken), Term("clientId", clientId))
                : Any(Wildcard("clientName", normalizedToken)),
            "resource" or "resourceid" or "resourcename" => long.TryParse(normalizedToken, out var resourceId)
                ? Any(MultiMatch(normalizedToken, "resourceName"), Wildcard("resourceName", normalizedToken),
                    Term("resourceId", resourceId))
                : Any(MultiMatch(normalizedToken, "resourceName"), Wildcard("resourceName", normalizedToken)),
            "remote" or "remoteaddress" => Any(Wildcard("remoteAddress", normalizedToken)),
            "contenttype" =>
                Any(Wildcard("requestContentType", normalizedToken), Wildcard("responseContentType", normalizedToken),
                    Term("responseBodyType", normalizedToken)),
            "responsebodytype" or "responsedatatype" => Term("responseBodyType", normalizedToken),
            "error" => Any(MultiMatch(normalizedToken, "error"), Wildcard("error", normalizedToken)),
            "requestheaders" =>
                Any(MultiMatch(normalizedToken, "requestHeaders"), Wildcard("requestHeaders", normalizedToken)),
            "responseheaders" =>
                Any(MultiMatch(normalizedToken, "responseHeaders"), Wildcard("responseHeaders", normalizedToken)),
            "headers" => Any(MultiMatch(normalizedToken, "requestHeaders", "responseHeaders"),
                Wildcard("requestHeaders", normalizedToken), Wildcard("responseHeaders", normalizedToken)),
            "requestbody" =>
                Any(MultiMatch(normalizedToken, "requestPreviewText"), Wildcard("requestPreviewText", normalizedToken)),
            "responsebody" =>
                Any(MultiMatch(normalizedToken, "responsePreviewText"), Wildcard("responsePreviewText", normalizedToken)),
            "body" => Any(MultiMatch(normalizedToken, "requestPreviewText", "responsePreviewText"),
                Wildcard("requestPreviewText", normalizedToken), Wildcard("responsePreviewText", normalizedToken)),
            "all" => Any(SummaryQuery(normalizedToken),
                MultiMatch(normalizedToken, "requestHeaders", "responseHeaders", "requestPreviewText", "responsePreviewText"),
                Wildcard("requestHeaders", normalizedToken), Wildcard("responseHeaders", normalizedToken),
                Wildcard("requestPreviewText", normalizedToken), Wildcard("responsePreviewText", normalizedToken)),
            _ => SummaryQuery(normalizedToken),
        };
    }

    private static string NormalizeHttpSearchField(string? field) =>
        (field ?? string.Empty).Trim().ToLowerInvariant().Replace("_", string.Empty).Replace("-", string.Empty);

    private static object SummaryQuery(string token)
    {
        var should = new List<object>
        {
            MultiMatch(token, "resourceName", "relativePath", "rawQuery", "error"),
            Wildcard("clientName", token),
            Wildcard("route", token),
            Wildcard("method", token),
            Wildcard("remoteAddress", token),
            Wildcard("requestContentType", token),
            Wildcard("responseContentType", token),
            Wildcard("responseBodyType", token),
            Wildcard("capturedAt", token),
        };
        if (long.TryParse(token, out var number))
        {
            should.Add(Term("id", number));
            should.Add(Term("clientId", number));
            should.Add(Term("statusCode", number));
            should.Add(Term("resourceId", number));
        }
        return Any(should.ToArray());
    }

    private static object ResponseBodyTypeQuery(string bodyType)
    {
        var should = new List<object> { Term("responseBodyType", bodyType) };
        if (bodyType == "empty")
        {
            should.Add(Term("responseBytes", 0));
        }
        else
        {
            should.AddRange(ResponseContentTypePatterns(bodyType).Select(pattern => Wildcard("responseContentType", pattern)));
        }
        return Any(should.ToArray());
    }

    private static IEnumerable<string> ResponseContentTypePatterns(string bodyType) => bodyType switch
    {
        "json" => ["application/json", "+json"],
        "html" => ["text/html"],
        "xml" => ["application/xml", "text/xml", "+xml"],
        "image" => ["image/"],
        "video" => ["video/"],
        "audio" => ["audio/"],
        "form" => ["application/x-www-form-urlencoded", "multipart/form-data"],
        "script" => ["javascript", "ecmascript"],
        "text" => ["text/"],
        "binary" => ["application/octet-stream", "application/pdf", "application/zip", "application/x-", "application/vnd."],
        _ => [],
    };

    private static object Term(string field, object value) =>
        new Dictionary<string, object?> { ["term"] = new Dictionary<string, object?> { [field] = value } };

    private static object Terms(string field, IEnumerable<long> values) =>
        new Dictionary<string, object?> { ["terms"] = new Dictionary<string, object?> { [field] = values } };

    private static object Wildcard(string field, string value) =>
        new Dictionary<string, object?>
        {
            ["wildcard"] = new Dictionary<string, object?>
            {
                [field] = new { value = "*" + EscapeWildcard(value) + "*", case_insensitive = true },
            },
        };

    private static object MultiMatch(string query, params string[] fields) =>
        new Dictionary<string, object?> { ["multi_match"] = new { query, fields } };

    private static object Any(params object[] queries) =>
        new Dictionary<string, object?>
        {
            ["bool"] = new Dictionary<string, object?> { ["should"] = queries, ["minimum_should_match"] = 1 },
        };

    private static object NoMatch() => Term("_id", "__shuai_tunnel_no_match__");

    private static string EscapeWildcard(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("*", "\\*", StringComparison.Ordinal)
        .Replace("?", "\\?", StringComparison.Ordinal);

    private static int TotalPages(long total, int size) =>
        size <= 0 || total == 0 ? 0 : (int)Math.Ceiling(total / (double)size);

    private long DocumentId(long existing)
    {
        if (existing > 0)
        {
            return existing;
        }
        var millis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var sequence = Interlocked.Increment(ref _sequence) & 0xfffffL;
        return (millis << 20) | sequence;
    }

    private static string Escape(string value) => Uri.EscapeDataString(value);

    private static object HttpMapping() => new { mappings = new { properties = HttpProperties() } };
    private static object TcpMapping() => new { mappings = new { properties = TcpProperties() } };

    private static Dictionary<string, object> HttpProperties() => new()
    {
        ["id"] = Type("long"),
        ["tenantId"] = Type("keyword"),
        ["clientId"] = Type("long"),
        ["clientName"] = Type("keyword"),
        ["route"] = Type("keyword"),
        ["resourceId"] = Type("long"),
        ["resourceName"] = Type("text"),
        ["method"] = Type("keyword"),
        ["relativePath"] = Type("text"),
        ["rawQuery"] = Type("text"),
        ["statusCode"] = Type("integer"),
        ["success"] = Type("boolean"),
        ["error"] = Type("text"),
        ["remoteAddress"] = Type("keyword"),
        ["requestBytes"] = Type("long"),
        ["responseBytes"] = Type("long"),
        ["elapsedMs"] = Type("long"),
        ["requestContentType"] = Type("keyword"),
        ["responseContentType"] = Type("keyword"),
        ["responseBodyType"] = Type("keyword"),
        ["requestHeaders"] = Type("text"),
        ["responseHeaders"] = Type("text"),
        ["requestPreviewHex"] = Type("text"),
        ["requestPreviewText"] = Type("text"),
        ["responsePreviewHex"] = Type("text"),
        ["responsePreviewText"] = Type("text"),
        ["requestTruncated"] = Type("boolean"),
        ["responseTruncated"] = Type("boolean"),
        ["capturedAt"] = Type("keyword"),
    };

    private static Dictionary<string, object> TcpProperties() => new()
    {
        ["id"] = Type("long"),
        ["tenantId"] = Type("keyword"),
        ["clientId"] = Type("long"),
        ["clientName"] = Type("keyword"),
        ["listenPort"] = Type("integer"),
        ["resourceId"] = Type("long"),
        ["resourceName"] = Type("text"),
        ["channelId"] = Type("keyword"),
        ["direction"] = Type("keyword"),
        ["remoteAddress"] = Type("keyword"),
        ["sourceAddress"] = Type("keyword"),
        ["sourcePort"] = Type("integer"),
        ["destinationAddress"] = Type("keyword"),
        ["destinationPort"] = Type("integer"),
        ["streamOffset"] = Type("long"),
        ["streamEndOffset"] = Type("long"),
        ["frameIndex"] = Type("long"),
        ["payloadBytes"] = Type("long"),
        ["payloadData"] = Type("binary"),
        ["payloadPreviewHex"] = Type("text"),
        ["payloadPreviewText"] = Type("text"),
        ["truncated"] = Type("boolean"),
        ["frameTime"] = Type("keyword"),
    };

    private static object Type(string type) => new { type };

    private sealed record HttpDocument
    {
        public string? DocumentId { get; init; }
        public long Id { get; init; }
        public string TenantId { get; init; } = "default";
        public long ClientId { get; init; }
        public string ClientName { get; init; } = string.Empty;
        public string Route { get; init; } = string.Empty;
        public long? ResourceId { get; init; }
        public string? ResourceName { get; init; }
        public string Method { get; init; } = string.Empty;
        public string RelativePath { get; init; } = "/";
        public string? RawQuery { get; init; }
        public int StatusCode { get; init; }
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? RemoteAddress { get; init; }
        public long RequestBytes { get; init; }
        public long ResponseBytes { get; init; }
        public long ElapsedMs { get; init; }
        public string? RequestContentType { get; init; }
        public string? ResponseContentType { get; init; }
        public string ResponseBodyType { get; init; } = "empty";
        public string? RequestHeaders { get; init; }
        public string? ResponseHeaders { get; init; }
        public string? RequestPreviewHex { get; init; }
        public string? RequestPreviewText { get; init; }
        public string? ResponsePreviewHex { get; init; }
        public string? ResponsePreviewText { get; init; }
        public bool RequestTruncated { get; init; }
        public bool ResponseTruncated { get; init; }
        public string CapturedAt { get; init; } = DateTimeOffset.UtcNow.ToString("O");

        public static HttpDocument FromEntity(HttpTrafficExchange exchange, long id) => new()
        {
            DocumentId = id.ToString(CultureInfo.InvariantCulture),
            Id = id,
            TenantId = exchange.TenantId,
            ClientId = exchange.ClientId,
            ClientName = exchange.ClientName,
            Route = exchange.Route,
            ResourceId = exchange.ResourceId,
            ResourceName = exchange.ResourceName,
            Method = exchange.Method,
            RelativePath = exchange.RelativePath,
            RawQuery = exchange.RawQuery,
            StatusCode = exchange.StatusCode,
            Success = exchange.Success,
            Error = exchange.Error,
            RemoteAddress = exchange.RemoteAddress,
            RequestBytes = exchange.RequestBytes,
            ResponseBytes = exchange.ResponseBytes,
            ElapsedMs = exchange.ElapsedMs,
            RequestContentType = exchange.RequestContentType,
            ResponseContentType = exchange.ResponseContentType,
            ResponseBodyType = NormalizeBodyType(exchange.ResponseBodyType, exchange.ResponseContentType,
                exchange.ResponseBytes),
            RequestHeaders = exchange.RequestHeaders,
            ResponseHeaders = exchange.ResponseHeaders,
            RequestPreviewHex = exchange.RequestPreviewHex,
            RequestPreviewText = exchange.RequestPreviewText,
            ResponsePreviewHex = exchange.ResponsePreviewHex,
            ResponsePreviewText = exchange.ResponsePreviewText,
            RequestTruncated = exchange.RequestTruncated,
            ResponseTruncated = exchange.ResponseTruncated,
            CapturedAt = exchange.CapturedAt.ToString("O"),
        };

        public HttpTrafficExchangeView ToView(bool includeDetail) => new(
            Id.ToString(CultureInfo.InvariantCulture),
            ClientId,
            ClientName,
            Route,
            ResourceId,
            ResourceName,
            Method,
            RelativePath,
            RawQuery,
            StatusCode,
            Success,
            Error,
            RemoteAddress,
            RequestBytes,
            ResponseBytes,
            ElapsedMs,
            RequestContentType,
            ResponseContentType,
            NormalizeBodyType(ResponseBodyType, ResponseContentType, ResponseBytes),
            includeDetail ? RequestHeaders : null,
            includeDetail ? ResponseHeaders : null,
            includeDetail ? RequestPreviewHex : null,
            includeDetail ? RequestPreviewText : null,
            includeDetail ? ResponsePreviewHex : null,
            includeDetail ? ResponsePreviewText : null,
            RequestTruncated,
            ResponseTruncated,
            CapturedAt);
    }

    private sealed record TcpDocument
    {
        public string? DocumentId { get; init; }
        public long Id { get; init; }
        public string TenantId { get; init; } = "default";
        public long ClientId { get; init; }
        public string ClientName { get; init; } = string.Empty;
        public int ListenPort { get; init; }
        public long? ResourceId { get; init; }
        public string? ResourceName { get; init; }
        public string ChannelId { get; init; } = string.Empty;
        public string Direction { get; init; } = string.Empty;
        public string? RemoteAddress { get; init; }
        public string? SourceAddress { get; init; }
        public int? SourcePort { get; init; }
        public string? DestinationAddress { get; init; }
        public int? DestinationPort { get; init; }
        public long StreamOffset { get; init; }
        public long StreamEndOffset { get; init; }
        public long FrameIndex { get; init; }
        public long PayloadBytes { get; init; }
        public string PayloadData { get; init; } = string.Empty;
        public string? PayloadPreviewHex { get; init; }
        public string? PayloadPreviewText { get; init; }
        public bool Truncated { get; init; }
        public string FrameTime { get; init; } = DateTimeOffset.UtcNow.ToString("O");

        public static TcpDocument FromEntity(TcpTrafficFrame frame, long id) => new()
        {
            DocumentId = id.ToString(CultureInfo.InvariantCulture),
            Id = id,
            TenantId = frame.TenantId,
            ClientId = frame.ClientId,
            ClientName = frame.ClientName,
            ListenPort = frame.ListenPort,
            ResourceId = frame.ResourceId,
            ResourceName = frame.ResourceName,
            ChannelId = frame.ChannelId,
            Direction = frame.Direction,
            RemoteAddress = frame.RemoteAddress,
            SourceAddress = frame.SourceAddress,
            SourcePort = frame.SourcePort,
            DestinationAddress = frame.DestinationAddress,
            DestinationPort = frame.DestinationPort,
            StreamOffset = frame.StreamOffset,
            StreamEndOffset = frame.StreamEndOffset,
            FrameIndex = frame.FrameIndex,
            PayloadBytes = frame.PayloadBytes,
            PayloadData = frame.PayloadData.Length == 0 ? string.Empty : Convert.ToBase64String(frame.PayloadData),
            PayloadPreviewHex = frame.PayloadPreviewHex,
            PayloadPreviewText = frame.PayloadPreviewText,
            Truncated = frame.Truncated,
            FrameTime = frame.FrameTime.ToString("O"),
        };

        public TcpTrafficFrameView ToView(bool includePayload) => new(
            Id.ToString(CultureInfo.InvariantCulture),
            ClientId,
            ClientName,
            ListenPort,
            ResourceId,
            ResourceName,
            ChannelId,
            Direction,
            RemoteAddress,
            SourceAddress,
            SourcePort,
            DestinationAddress,
            DestinationPort,
            StreamOffset,
            StreamEndOffset,
            FrameIndex,
            PayloadBytes,
            includePayload ? PayloadData : null,
            PayloadPreviewHex,
            PayloadPreviewText,
            Truncated,
            FrameTime);
    }

    private sealed record EsSearchResponse<T>
    {
        public EsHits<T> Hits { get; init; } = new();
    }

    private sealed record EsHits<T>
    {
        public EsTotal Total { get; init; } = new();
        public IReadOnlyList<EsHit<T>> Hits { get; init; } = [];
    }

    private sealed record EsTotal
    {
        public long Value { get; init; }
    }

    private sealed record EsHit<T>
    {
        [JsonPropertyName("_id")]
        public string Id { get; init; } = string.Empty;

        [JsonPropertyName("_source")]
        public T Source { get; init; } = default!;
    }

    private sealed record EsStatsResponse
    {
        public Dictionary<string, EsIndexStats> Indices { get; init; } = [];
    }

    private sealed record EsIndexStats
    {
        public EsTotalStats Total { get; init; } = new();
    }

    private sealed record EsTotalStats
    {
        public EsStoreStats Store { get; init; } = new();
    }

    private sealed record EsStoreStats
    {
        [JsonPropertyName("size_in_bytes")]
        public long SizeInBytes { get; init; }

        [JsonPropertyName("total_data_set_size_in_bytes")]
        public long TotalDataSetSizeInBytes { get; init; }
    }

    private static string NormalizeBodyType(string? bodyType, string? contentType, long bytes)
    {
        var normalized = (bodyType ?? string.Empty).Trim().ToLowerInvariant();
        return normalized is "empty" or "json" or "html" or "xml" or "image" or "video" or "audio"
            or "form" or "script" or "text" or "binary"
            ? normalized
            : Classify(contentType, bytes);
    }

    private static string Classify(string? contentType, long bytes)
    {
        if (bytes <= 0)
        {
            return "empty";
        }
        var media = (contentType ?? string.Empty).Split(';', 2)[0].Trim().ToLowerInvariant();
        if (media == "application/json" || media.EndsWith("+json", StringComparison.Ordinal)) return "json";
        if (media == "text/html") return "html";
        if (media == "application/xml" || media == "text/xml" || media.EndsWith("+xml", StringComparison.Ordinal)) return "xml";
        if (media.StartsWith("image/", StringComparison.Ordinal)) return "image";
        if (media.StartsWith("video/", StringComparison.Ordinal)) return "video";
        if (media.StartsWith("audio/", StringComparison.Ordinal)) return "audio";
        if (media is "application/x-www-form-urlencoded" or "multipart/form-data") return "form";
        if (media.Contains("javascript", StringComparison.Ordinal) || media.Contains("ecmascript", StringComparison.Ordinal)) return "script";
        if (media.StartsWith("text/", StringComparison.Ordinal)) return "text";
        return "binary";
    }
}
