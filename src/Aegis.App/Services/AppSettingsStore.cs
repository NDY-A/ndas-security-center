using System.Text.Json;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;

namespace Aegis.App.Services;

public sealed class AppSettingsStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public AppSettingsStore(string path)
    {
        _path = path;
    }

    public string? LoadWarning { get; private set; }

    public async Task<AppSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new InvalidOperationException("设置路径无效。");
            }

            Directory.CreateDirectory(directory);
            var temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await JsonSerializer.SerializeAsync(stream, settings, JsonDefaults.WebIndented, cancellationToken).ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }

                File.Move(temporary, _path, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    try
                    {
                        File.Delete(temporary);
                    }
                    catch (IOException)
                    {
                        // Best-effort cleanup.
                    }
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<AppSettings> LoadCoreAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new AppSettings();
        }

        try
        {
            var info = new FileInfo(_path);
            if (info.Length is <= 0 or > 1024 * 1024)
            {
                throw new InvalidDataException("设置文件大小异常。");
            }

            await using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous);
            var settings = await JsonSerializer.DeserializeAsync<AppSettings>(stream, JsonDefaults.Web, cancellationToken).ConfigureAwait(false) ?? new AppSettings();
            Normalize(settings);
            return settings;
        }
        catch (Exception exception) when (exception is IOException or JsonException or InvalidDataException or UnauthorizedAccessException)
        {
            LoadWarning = "设置文件无法读取，已使用默认设置。";
            return new AppSettings();
        }
    }

    private static void Normalize(AppSettings settings)
    {
        settings.CloudEndpoint = settings.CloudEndpoint?.Trim() ?? string.Empty;
        settings.CloudPolicy = Enum.IsDefined(settings.CloudPolicy) ? settings.CloudPolicy : CloudQueryPolicy.SuspiciousOnly;
        settings.AgentApiPort = settings.AgentApiPort is >= 1024 and <= 65_535 ? settings.AgentApiPort : 17_483;
        settings.Theme = Enum.IsDefined(settings.Theme) ? settings.Theme : AppThemePreference.System;
        settings.MaxFileSizeBytes = Math.Clamp(settings.MaxFileSizeBytes, 1024 * 1024, 2L * 1024 * 1024 * 1024);
        settings.Exclusions ??= new List<string>();
        settings.Exclusions = settings.Exclusions
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(256)
            .ToList();
        settings.AllowedHashes ??= new List<string>();
        settings.AllowedHashes = settings.AllowedHashes
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim().ToLowerInvariant())
            .Where(value => value.Length == 64 && value.All(character => char.IsAsciiHexDigit(character)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(512)
            .ToList();
    }
}
