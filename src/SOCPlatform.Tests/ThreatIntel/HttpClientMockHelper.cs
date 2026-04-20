using System.Net;

namespace SOCPlatform.Tests.ThreatIntel;

/// <summary>
/// Tiny helper to build an IHttpClientFactory that returns an HttpClient backed
/// by a stub handler — lets adapter tests assert on payloads without spinning up
/// the real HTTP stack.
/// </summary>
internal static class HttpClientMockHelper
{
    public static IHttpClientFactory ForResponse(
        string namedClient,
        HttpStatusCode status,
        string? jsonBody = null,
        Uri? baseAddress = null,
        Action<HttpRequestMessage>? onRequest = null)
    {
        var handler = new StubHandler(status, jsonBody, onRequest);
        // Default base address so adapters that issue relative URLs don't blow up
        // with "InvalidOperationException: absolute URI required".
        var client = new HttpClient(handler) { BaseAddress = baseAddress ?? new Uri("https://test.invalid/") };
        return new SingleClientFactory(namedClient, client);
    }

    private sealed class SingleClientFactory : IHttpClientFactory
    {
        private readonly string _name;
        private readonly HttpClient _client;
        public SingleClientFactory(string name, HttpClient client) { _name = name; _client = client; }
        public HttpClient CreateClient(string name) => name == _name
            ? _client
            : throw new InvalidOperationException($"Unexpected client name '{name}', test wired '{_name}'");
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string? _body;
        private readonly Action<HttpRequestMessage>? _onRequest;
        public StubHandler(HttpStatusCode status, string? body, Action<HttpRequestMessage>? onRequest)
        { _status = status; _body = body; _onRequest = onRequest; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onRequest?.Invoke(request);
            var resp = new HttpResponseMessage(_status);
            if (_body is not null)
                resp.Content = new StringContent(_body, System.Text.Encoding.UTF8, "application/json");
            return Task.FromResult(resp);
        }
    }
}
