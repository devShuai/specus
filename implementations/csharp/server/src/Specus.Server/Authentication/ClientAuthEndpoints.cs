namespace Specus.Server.Authentication;

public static class ClientAuthEndpoints
{
    public static void MapClientAuthApi(this WebApplication app)
    {
        app.MapPost("/api/client/auth/login",
            async (HttpContext context, ClientAuthLoginRequest? request,
                ClientAccountService service, CancellationToken cancellationToken) =>
            {
                if (request is null)
                {
                    return Results.BadRequest(new { error = "登录请求不能为空" });
                }
                try
                {
                    var response = await service.LoginAsync(
                            request,
                            context.Request.Host.Host,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return Results.Ok(response);
                }
                catch (ArgumentException ex)
                {
                    return Results.BadRequest(new { error = ex.Message });
                }
                catch (InvalidOperationException ex)
                {
                    return Results.Conflict(new { error = ex.Message });
                }
            });
    }
}
