using Aegis.ML;

Console.WriteLine($"available={MlEngine.IsAvailable} status={MlEngine.Status}");
foreach (var path in args)
{
    var ok = MlEngine.TryScore(path, out var probability, out var error);
    Console.WriteLine(ok
        ? $"OK   score={probability:F4}  {path}"
        : $"FAIL {error}  {path}");
}
