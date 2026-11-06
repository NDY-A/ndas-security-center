using Aegis.Core.Infrastructure;
using Aegis.Core.Signatures;

namespace Aegis.Service;

public sealed class SignatureLocator
{
    private readonly string _seedDirectory;

    public SignatureLocator(string seedDirectory)
    {
        _seedDirectory = seedDirectory;
    }

    public async Task<SignatureSnapshot?> LoadBestAsync(CancellationToken cancellationToken)
    {
        SignatureSnapshot? best = null;
        foreach (var root in EnumerateRoots())
        {
            try
            {
                if (!File.Exists(Path.Combine(root, "current", "manifest.json")))
                {
                    continue;
                }

                var repository = new SignatureRepository(root, _seedDirectory);
                var snapshot = await repository.LoadAsync(cancellationToken).ConfigureAwait(false);
                if (!snapshot.IsSeed && (best is null || snapshot.FetchedAt > best.FetchedAt))
                {
                    best = snapshot;
                }
            }
            catch
            {
                // A broken user update must not prevent the service from using the seed.
            }
        }

        if (best is not null)
        {
            return best;
        }

        if (!Directory.Exists(_seedDirectory))
        {
            return null;
        }

        var seedRepository = new SignatureRepository(ServicePaths.SharedSignatureRoot, _seedDirectory);
        return await seedRepository.LoadAsync(cancellationToken).ConfigureAwait(false);
    }

    private static IEnumerable<string> EnumerateRoots()
    {
        yield return ServicePaths.SharedSignatureRoot;
        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(30)))
        {
            yield return Path.Combine(profile.ProfilePath, "AppData", "Local", "NDAS", "signatures");
        }
    }
}
