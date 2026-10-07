using System.Net;
using System.Text;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

// Java's SpringDataElasticsearchHttpTrafficExchangeStore.putBinaryBodyMapping: an HTTP index that
// exists already gets requestBodyData and responseBodyData as binary; a refusal leaves it as it is.
public sealed class ElasticsearchBodyMappingTests
{
    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task ExistingHttpIndexGetsTheBinaryBodyFields(HttpStatusCode mappingAnswer)
    {
        var handler = new RecordingHandler(indexExists: true, mappingAnswer);
        var client = NewClient(handler);

        var found = await client.GetHttpExchangeAsync(Admin, [1L], 42L, CancellationToken.None);

        Assert.Null(found);
        var update = Assert.Single(handler.Requests, request => request.Path.EndsWith("/_mapping", StringComparison.Ordinal));
        Assert.Equal("PUT /specus-http-traffic/_mapping", $"{update.Method} {update.Path}");
        Assert.Contains("\"requestBodyData\":{\"type\":\"binary\"}", update.Body, StringComparison.Ordinal);
        Assert.Contains("\"responseBodyData\":{\"type\":\"binary\"}", update.Body, StringComparison.Ordinal);
        // The search still ran, whether or not the update was taken.
        Assert.Contains(handler.Requests, request => request.Path.EndsWith("/_search", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NewHttpIndexIsCreatedWithTheBodyFieldsAndNoUpdate()
    {
        var handler = new RecordingHandler(indexExists: false, HttpStatusCode.OK);
        var client = NewClient(handler);

        await client.GetHttpExchangeAsync(Admin, [1L], 42L, CancellationToken.None);

        Assert.DoesNotContain(handler.Requests, request => request.Path.EndsWith("/_mapping", StringComparison.Ordinal));
        var create = Assert.Single(handler.Requests, request => request.Method == "PUT");
        Assert.Equal("/specus-http-traffic", create.Path);
        Assert.Contains("\"requestBodyData\":{\"type\":\"binary\"}", create.Body, StringComparison.Ordinal);
    }

    private static readonly ManagementContext Admin = new("default", "admin", ManagementRole.Admin, true);

    private static ElasticsearchTrafficDetailClient NewClient(RecordingHandler handler) => new(
        Options.Create(new ElasticsearchOptions { Uris = "http://127.0.0.1:9200" }),
        new StaticHttpClientFactory(new HttpClient(handler)));

    private sealed record RecordedRequest(string Method, string Path, string Body);

    private sealed class RecordingHandler(bool indexExists, HttpStatusCode mappingAnswer) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add(new RecordedRequest(request.Method.Method, path, body));
            if (request.Method == HttpMethod.Head)
            {
                return new HttpResponseMessage(indexExists ? HttpStatusCode.OK : HttpStatusCode.NotFound);
            }
            if (path.EndsWith("/_mapping", StringComparison.Ordinal))
            {
                return Json(mappingAnswer, mappingAnswer == HttpStatusCode.OK
                    ? "{\"acknowledged\":true}"
                    : "{\"error\":{\"type\":\"illegal_argument_exception\"}}");
            }
            if (path.EndsWith("/_search", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK, "{\"hits\":{\"total\":{\"value\":0},\"hits\":[]}}");
            }
            return Json(HttpStatusCode.OK, "{\"acknowledged\":true}");
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
    }

    private sealed class StaticHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
}
