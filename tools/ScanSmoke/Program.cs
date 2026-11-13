using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
using Aegis.Core.Signatures;
using Aegis.ML;

if (args.Length < 2)
{
    Console.WriteLine("usage: ScanSmoke <seedDir> <file> [file...]");
    return 2;
}

var repository = new SignatureRepository(AppPaths.SignatureRoot, args[0]);
var snapshot = await repository.LoadAsync();
Console.WriteLine(
    $"signatures={snapshot.Version} hashes={snapshot.HashCount} yara={snapshot.YaraRuleCount} " +
    $"specialPaths={snapshot.SpecialPathCount} ml={(MlEngine.IsAvailable ? MlEngine.Status : "unavailable")}");

var scanner = new AegisScanner(snapshot);
foreach (var path in args[1..])
{
    try
    {
        var result = await scanner.ScanFileAsync(path, ScanOptions.Default);
        Console.WriteLine($"{result.Verdict} score={result.Score} name={result.ThreatName} file={result.FileName}");
        foreach (var detection in result.Detections)
        {
            Console.WriteLine($"  [{detection.Source}] {detection.Score} {detection.Name}");
        }

        foreach (var note in result.Notes)
        {
            Console.WriteLine($"  note: {note}");
        }
    }
    catch (Exception exception)
    {
        Console.WriteLine($"ERROR {path}: {exception.GetType().Name} {exception.Message}");
    }
}

return 0;
