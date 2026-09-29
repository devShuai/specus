using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Specus.Client.Tests")]
[assembly: InternalsVisibleTo("Specus.Client.Benchmarks")]
// The desktop page edits the same rules through the same plan as the commands and the local page.
[assembly: InternalsVisibleTo("specus-desktop")]
