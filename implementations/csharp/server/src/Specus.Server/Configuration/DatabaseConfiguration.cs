using System.Globalization;

namespace Specus.Server.Configuration;

internal sealed record ResolvedDatabaseConfiguration(
    string Provider,
    string ConnectionString,
    int PoolSize,
    int BatchSize);

internal static class DatabaseConfiguration
{
    public static ResolvedDatabaseConfiguration Resolve(DatabaseOptions options,
        string? existingConnectionString)
    {
        var provider = ResolveProvider(options);
        var connectionString = string.IsNullOrWhiteSpace(options.Url)
            ? existingConnectionString
            : ConvertJdbcUrl(options.Url, provider);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            connectionString = "Data Source=./specus.db";
        }

        connectionString = ApplyCredentials(connectionString, provider,
            options.Username, options.Password);
        connectionString = ApplyPoolSize(connectionString, provider, options.PoolSize);
        return new ResolvedDatabaseConfiguration(provider, connectionString,
            Math.Max(1, options.PoolSize), Math.Max(1, options.BatchSize));
    }

    private static string ResolveProvider(DatabaseOptions options)
    {
        var evidence = string.Join(' ', options.Url, options.Driver, options.Dialect).ToLowerInvariant();
        if (evidence.Contains("postgres", StringComparison.Ordinal)
            || evidence.Contains("pgsql", StringComparison.Ordinal))
        {
            return "postgres";
        }
        if (evidence.Contains("mysql", StringComparison.Ordinal)
            || evidence.Contains("maria", StringComparison.Ordinal))
        {
            return "mysql";
        }
        if (evidence.Contains("sqlite", StringComparison.Ordinal))
        {
            return "sqlite";
        }
        return options.Provider.Trim().ToLowerInvariant() switch
        {
            "postgres" or "postgresql" or "npgsql" => "postgres",
            "mysql" or "mariadb" => "mysql",
            "sqlite" or "" => "sqlite",
            var unknown => throw new InvalidOperationException(
                $"Unknown {DatabaseOptions.SectionName}:Provider '{unknown}'. Use 'sqlite', 'postgres', or 'mysql'."),
        };
    }

    private static string ConvertJdbcUrl(string value, string provider)
    {
        var url = value.Trim();
        if (!url.StartsWith("jdbc:", StringComparison.OrdinalIgnoreCase))
        {
            return url;
        }
        if (provider == "sqlite")
        {
            const string prefix = "jdbc:sqlite:";
            if (!url.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("SQLite JDBC URL must start with jdbc:sqlite:");
            }
            var path = url[prefix.Length..];
            return $"Data Source={Quote(path.Length == 0 ? "./specus.db" : path)}";
        }

        var uriText = url["jdbc:".Length..];
        if (!Uri.TryCreate(uriText, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Invalid JDBC database URL for {provider}");
        }
        var database = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        if (string.IsNullOrWhiteSpace(database))
        {
            throw new InvalidOperationException($"JDBC database URL has no database name for {provider}");
        }
        var port = uri.IsDefaultPort ? (provider == "postgres" ? 5432 : 3306) : uri.Port;
        var parts = new List<string>
        {
            provider == "postgres" ? $"Host={Quote(uri.Host)}" : $"Server={Quote(uri.Host)}",
            $"Port={port.ToString(CultureInfo.InvariantCulture)}",
            $"Database={Quote(database)}",
        };
        AppendSupportedQuery(parts, uri.Query, provider);
        return string.Join(';', parts);
    }

    private static void AppendSupportedQuery(List<string> parts, string query, string provider)
    {
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            var rawKey = separator < 0 ? pair : pair[..separator];
            var rawValue = separator < 0 ? string.Empty : pair[(separator + 1)..];
            var key = Uri.UnescapeDataString(rawKey).Trim();
            var value = Uri.UnescapeDataString(rawValue.Replace('+', ' ')).Trim();
            var mapped = (provider, key.ToLowerInvariant()) switch
            {
                ("postgres", "sslmode") => "SSL Mode",
                ("postgres", "currentschema") => "Search Path",
                ("postgres", "connecttimeout") => "Timeout",
                ("postgres", "sockettimeout") => "Command Timeout",
                ("postgres", "applicationname") => "Application Name",
                ("mysql", "connecttimeout") => "Connection Timeout",
                ("mysql", "characterset") or ("mysql", "characterencoding") => "Character Set",
                ("mysql", "usessl") => "SslMode",
                ("mysql", "requiressl") => "SslMode",
                ("mysql", "allowpublickeyretrieval") => "AllowPublicKeyRetrieval",
                _ => null,
            };
            if (mapped is null)
            {
                continue;
            }
            if (provider == "mysql" && key.Equals("useSSL", StringComparison.OrdinalIgnoreCase))
            {
                value = bool.TryParse(value, out var enabled) && enabled ? "Required" : "None";
            }
            else if (provider == "mysql" && key.Equals("requireSSL", StringComparison.OrdinalIgnoreCase))
            {
                value = bool.TryParse(value, out var required) && required ? "Required" : "Preferred";
            }
            else if (provider == "mysql"
                     && key.Equals("characterEncoding", StringComparison.OrdinalIgnoreCase)
                     && (value.Equals("UTF-8", StringComparison.OrdinalIgnoreCase)
                         || value.Equals("UTF8", StringComparison.OrdinalIgnoreCase)))
            {
                value = "utf8mb4";
            }
            parts.Add($"{mapped}={Quote(value)}");
        }
    }

    private static string ApplyCredentials(string connectionString, string provider,
        string? username, string? password)
    {
        var parts = new List<string> { connectionString.Trim().TrimEnd(';') };
        if (!string.IsNullOrWhiteSpace(username))
        {
            parts.Add(provider == "postgres"
                ? $"Username={Quote(username.Trim())}"
                : $"User ID={Quote(username.Trim())}");
        }
        if (!string.IsNullOrEmpty(password))
        {
            parts.Add($"Password={Quote(password)}");
        }
        return string.Join(';', parts.Where(part => part.Length > 0));
    }

    private static string ApplyPoolSize(string connectionString, string provider, int poolSize)
    {
        if (provider == "sqlite" || poolSize <= 0)
        {
            return connectionString;
        }
        var key = provider == "postgres" ? "Maximum Pool Size" : "MaximumPoolSize";
        return $"{connectionString.TrimEnd(';')};{key}={poolSize.ToString(CultureInfo.InvariantCulture)}";
    }

    private static string Quote(string value) =>
        '"' + value.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
}
