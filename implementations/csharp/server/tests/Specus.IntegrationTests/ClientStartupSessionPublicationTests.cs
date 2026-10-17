using Specus.Server.Authentication;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

public sealed class ClientStartupSessionPublicationTests
{
    [Fact]
    public void PreparedTokenIsNotAuthorityUntilPublishedAndCannotOverwriteAnExistingSession()
    {
        var store = new ClientAuthSessionStore();
        var session = store.Prepare(new ClientCredential { Id = 1 }, new ClientIdentity { Id = 2 },
            new ClientAccount { Id = 3, ClientName = "publication" }, TimeSpan.FromHours(1),
            new ClientEnvironmentInfo { MachineFingerprint = "machine", OsUser = "user" });
        Assert.Null(store.Find(session.Id, session.AccessToken)); Assert.Null(store.FindById(session.Id));
        store.Publish(session);
        Assert.Same(session, store.Find(session.Id, session.AccessToken));
        Assert.Throws<InvalidOperationException>(() => store.Publish(session));
        Assert.Same(session, store.Find(session.Id, session.AccessToken));
    }
}
