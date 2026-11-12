using System.Text.Json;

namespace Aegis.Sandbox;

public sealed class ParsedSandboxReport
{
    public string? Sha256 { get; set; }
    public string? FileType { get; set; }
    public string? ReportVersion { get; set; }
    public double RuntimeSeconds { get; set; }
    public bool Truncated { get; set; }
    public List<string> SessionErrors { get; } = new();
    public List<string> RunErrors { get; } = new();
    public List<string> Strings { get; } = new();
    public List<string> DroppedFiles { get; } = new();
    public List<ParsedSandboxEvent> Events { get; } = new();
}

public sealed class ParsedSandboxEvent
{
    public required string Kind { get; init; }
    public string? ApiName { get; init; }
    public string? Path { get; init; }
    public string? CommandLine { get; init; }
    public bool CrossProcess { get; init; }
    public bool WritableExecutable { get; init; }
    public List<string> Arguments { get; init; } = new();
}

public static class SandboxReportParser
{
    private const int MaxEvents = 20_000;
    private const int MaxStrings = 4_000;
    private const int MaxArguments = 64;

    public static ParsedSandboxReport Parse(ReadOnlySpan<byte> json)
    {
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
        {
            MaxDepth = 64,
            AllowTrailingCommas = true
        });

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("沙箱报告不是 JSON 对象。");
        }

        var report = new ParsedSandboxReport
        {
            Sha256 = GetString(root, "sha256"),
            FileType = GetString(root, "file_type") ?? GetString(root, "filetype"),
            ReportVersion = GetString(root, "report_version") ?? GetString(root, "emu_version"),
            RuntimeSeconds = GetDouble(root, "emulation_total_runtime")
        };

        ReadErrors(root, report.SessionErrors);
        ReadStrings(root, report);
        ReadEntryPoints(root, report);
        return report;
    }

    private static void ReadEntryPoints(JsonElement root, ParsedSandboxReport report)
    {
        if (!root.TryGetProperty("entry_points", out var entryPoints) ||
            entryPoints.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var run in entryPoints.EnumerateArray())
        {
            if (run.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (run.TryGetProperty("error", out var runError) && runError.ValueKind == JsonValueKind.Object)
            {
                report.RunErrors.Add(FormatError(runError));
            }

            if (run.TryGetProperty("dropped_files", out var dropped) && dropped.ValueKind == JsonValueKind.Array)
            {
                foreach (var file in dropped.EnumerateArray())
                {
                    var path = file.ValueKind == JsonValueKind.Object ? GetString(file, "path") : null;
                    if (!string.IsNullOrWhiteSpace(path) && report.DroppedFiles.Count < MaxStrings)
                    {
                        report.DroppedFiles.Add(path);
                    }
                }
            }

            if (run.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in events.EnumerateArray())
                {
                    if (report.Events.Count >= MaxEvents)
                    {
                        report.Truncated = true;
                        break;
                    }

                    var parsed = ParseEvent(element);
                    if (parsed is not null)
                    {
                        report.Events.Add(parsed);
                    }
                }
            }

            // Speakeasy 1.5.x reports API calls under "apis" (plain argument
            // strings) instead of the newer "events" schema.
            if (run.TryGetProperty("apis", out var apis) && apis.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in apis.EnumerateArray())
                {
                    if (report.Events.Count >= MaxEvents)
                    {
                        report.Truncated = true;
                        break;
                    }

                    var parsed = ParseApiCall(element);
                    if (parsed is not null)
                    {
                        report.Events.Add(parsed);
                    }
                }
            }

            if (run.TryGetProperty("dynamic_code_segments", out var segments) &&
                segments.ValueKind == JsonValueKind.Array &&
                segments.GetArrayLength() > 0)
            {
                report.Events.Add(new ParsedSandboxEvent
                {
                    Kind = "mem_protect",
                    WritableExecutable = true
                });
            }
        }
    }

    private static ParsedSandboxEvent? ParseApiCall(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var apiName = GetString(element, "api_name");
        if (string.IsNullOrWhiteSpace(apiName))
        {
            return null;
        }

        var arguments = new List<string>();
        if (element.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Array)
        {
            foreach (var argument in args.EnumerateArray())
            {
                if (arguments.Count >= MaxArguments)
                {
                    break;
                }

                if (argument.ValueKind == JsonValueKind.String && argument.GetString() is { Length: > 0 } text)
                {
                    arguments.Add(text);
                }
                else if (argument.ValueKind == JsonValueKind.Object &&
                         GetString(argument, "display") is { Length: > 0 } display)
                {
                    arguments.Add(display);
                }
            }
        }

        return new ParsedSandboxEvent
        {
            Kind = "api",
            ApiName = apiName,
            Arguments = arguments
        };
    }

    private static ParsedSandboxEvent? ParseEvent(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var kind = GetString(element, "event");
        if (string.IsNullOrWhiteSpace(kind))
        {
            return null;
        }

        var kindLower = kind.ToLowerInvariant();
        string? apiName = null;
        string? path = null;
        string? commandLine = null;
        var crossProcess = false;
        var writableExecutable = false;
        var arguments = new List<string>();

        switch (kindLower)
        {
            case "api":
                apiName = GetString(element, "api_name");
                if (element.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Array)
                {
                    foreach (var argument in args.EnumerateArray())
                    {
                        if (arguments.Count >= MaxArguments)
                        {
                            break;
                        }

                        if (argument.ValueKind != JsonValueKind.Object)
                        {
                            continue;
                        }

                        var display = GetString(argument, "display");
                        if (!string.IsNullOrWhiteSpace(display))
                        {
                            arguments.Add(display);
                        }
                    }
                }

                break;

            case "process_create":
                path = GetString(element, "path");
                commandLine = GetString(element, "command_line");
                break;

            case "mem_alloc":
            case "mem_write":
            case "mem_protect":
            case "mem_free":
                path = GetString(element, "path");
                crossProcess = element.TryGetProperty("pid", out _);
                writableExecutable = HasExecutableProtection(element);
                break;

            case "thread_inject":
            case "thread_create":
                crossProcess = element.TryGetProperty("pid", out _);
                break;

            case "module_load":
                path = GetString(element, "path");
                break;
        }

        return new ParsedSandboxEvent
        {
            Kind = kindLower,
            ApiName = apiName,
            Path = path,
            CommandLine = commandLine,
            CrossProcess = crossProcess,
            WritableExecutable = writableExecutable,
            Arguments = arguments
        };
    }

    private static bool HasExecutableProtection(JsonElement element)
    {
        if (!element.TryGetProperty("protect", out var protect))
        {
            return false;
        }

        if (protect.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in protect.EnumerateArray())
            {
                if (value.ValueKind == JsonValueKind.String &&
                    value.GetString() is { } text &&
                    (text.Contains("EXECUTE_READWRITE", StringComparison.OrdinalIgnoreCase) ||
                     text.Contains("EXECUTE_WRITECOPY", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }
        else if (protect.ValueKind == JsonValueKind.String &&
                 protect.GetString() is { } single &&
                 (single.Contains("EXECUTE_READWRITE", StringComparison.OrdinalIgnoreCase) ||
                  single.Contains("EXECUTE_WRITECOPY", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }

    private static void ReadErrors(JsonElement root, List<string> errors)
    {
        if (!root.TryGetProperty("errors", out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object)
            {
                errors.Add(FormatError(item));
            }
        }
    }

    private static void ReadStrings(JsonElement root, ParsedSandboxReport report)
    {
        if (!root.TryGetProperty("strings", out var strings) || strings.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var scope in strings.EnumerateObject())
        {
            if (scope.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var encoding in scope.Value.EnumerateObject())
            {
                if (encoding.Value.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var value in encoding.Value.EnumerateArray())
                {
                    if (report.Strings.Count >= MaxStrings)
                    {
                        report.Truncated = true;
                        return;
                    }

                    if (value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text)
                    {
                        report.Strings.Add(text);
                    }
                }
            }
        }
    }

    private static string FormatError(JsonElement error)
    {
        var type = GetString(error, "type") ?? "error";
        var message = GetString(error, "message") ?? GetString(error, "context_summary");
        return string.IsNullOrWhiteSpace(message) ? type : $"{type}: {message}";
    }

    private static string? GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static double GetDouble(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return 0;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number))
        {
            return number;
        }

        return value.ValueKind == JsonValueKind.String &&
               double.TryParse(value.GetString(), out var parsed)
            ? parsed
            : 0;
    }
}
