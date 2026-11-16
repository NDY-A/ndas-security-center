using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Aegis.ML;

/// <summary>
/// Byte-level script classifier ("智能引擎 Lite"). Pure managed LightGBM
/// evaluation so the service needs no extra runtime; the feature pipeline is a
/// bit-exact port of the Python trainer (murmur3 hashed character 2-3 grams,
/// whitespace-run collapse, L2 normalisation, first 8192 code points).
/// </summary>
public static class ScriptEngine
{
    private const int Buckets = 4096;
    private const int MaxChars = 8192;
    private const int MaxFileBytes = 256 * 1024;

    private static readonly object Sync = new();
    private static readonly Regex WhitespaceRun = new(@"\s\s+", RegexOptions.Compiled);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private static bool _attempted;
    private static bool _available;
    private static string _status = "尚未初始化";
    private static string _version = string.Empty;
    private static TreeNode[] _trees = Array.Empty<TreeNode>();

    public static string Status
    {
        get
        {
            lock (Sync)
            {
                EnsureInitializedLocked();
                return _status;
            }
        }
    }

    public static bool IsAvailable
    {
        get
        {
            lock (Sync)
            {
                EnsureInitializedLocked();
                return _available;
            }
        }
    }

    public static string ModelVersion
    {
        get
        {
            lock (Sync)
            {
                EnsureInitializedLocked();
                return _available ? _version : string.Empty;
            }
        }
    }

    public static bool TryScoreBytes(byte[] data, out float probability, out string? error)
    {
        probability = 0f;
        error = null;
        lock (Sync)
        {
            EnsureInitializedLocked();
            if (!_available)
            {
                error = _status;
                return false;
            }
        }

        try
        {
            var text = Decode(data);
            if (text is null)
            {
                error = "脚本为空或超过 256KB";
                return false;
            }

            probability = Score(text);
            return true;
        }
        catch (Exception exception)
        {
            error = "脚本评分失败：" + exception.Message;
            return false;
        }
    }

    private static void EnsureInitializedLocked()
    {
        if (_attempted)
        {
            return;
        }

        _attempted = true;
        try
        {
            var modelPath = ResolveModelPath();
            if (modelPath is null)
            {
                _status = "未找到模型文件（ML\\script-ngram.json）";
                return;
            }

            var model = JsonSerializer.Deserialize<ModelFile>(File.ReadAllText(modelPath));
            if (model?.Trees is null || model.Trees.Count == 0)
            {
                _status = "模型文件为空或格式错误";
                return;
            }

            _trees = model.Trees.ToArray();
            _version = string.IsNullOrWhiteSpace(model.Version) ? "script-ngram" : model.Version!;
            _available = true;
            _status = $"已加载 {_version}（{_trees.Length} 棵树）";
        }
        catch (Exception exception)
        {
            _status = "初始化异常：" + exception.Message;
        }
    }

    private static string? ResolveModelPath()
    {
        var baseDirectory = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(baseDirectory, "ML", "script-ngram.json"),
            Path.Combine(baseDirectory, "script-ngram.json"),
            Path.Combine(baseDirectory, "Models", "script-ngram.json")
        };
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        var overridePath = Environment.GetEnvironmentVariable("NDAS_SCRIPT_ML_MODEL");
        if (!string.IsNullOrWhiteSpace(overridePath) && File.Exists(overridePath))
        {
            return overridePath;
        }

        return null;
    }

    private static string? Decode(byte[] data)
    {
        if (data.Length == 0 || data.Length > MaxFileBytes)
        {
            return null;
        }

        var span = data.AsSpan();
        if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF)
        {
            span = span[3..];
        }

        try
        {
            return StrictUtf8.GetString(span);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(data);
        }
    }

    private static float Score(string text)
    {
        var builder = new StringBuilder(Math.Min(text.Length, MaxChars));
        var taken = 0;
        foreach (var rune in text.EnumerateRunes())
        {
            if (taken++ >= MaxChars)
            {
                break;
            }

            builder.Append(rune.ToString());
        }

        var normalized = WhitespaceRun.Replace(builder.ToString(), " ");
        var runes = normalized.EnumerateRunes().ToArray();
        var counts = new int[Buckets];
        Span<byte> buffer = stackalloc byte[12];

        for (var n = 2; n <= 3; n++)
        {
            if (runes.Length < n)
            {
                continue;
            }

            for (var i = 0; i + n <= runes.Length; i++)
            {
                var length = 0;
                for (var k = 0; k < n; k++)
                {
                    length += runes[i + k].EncodeToUtf8(buffer[length..]);
                }

                var hash = MurmurHash3.Hash32(buffer[..length], 0);
                var index = (int)(Math.Abs((long)hash) % Buckets);
                counts[index]++;
            }
        }

        double sumSquares = 0;
        foreach (var count in counts)
        {
            sumSquares += (double)count * count;
        }

        var norm = Math.Sqrt(sumSquares);
        var features = new float[Buckets];
        if (norm > 0)
        {
            for (var i = 0; i < Buckets; i++)
            {
                features[i] = (float)(counts[i] / norm);
            }
        }

        double raw = 0;
        foreach (var tree in _trees)
        {
            raw += Evaluate(tree, features);
        }

        return (float)(1.0 / (1.0 + Math.Exp(-raw)));
    }

    private static double Evaluate(TreeNode node, float[] features)
    {
        while (node.Left is not null)
        {
            var value = features[node.SplitFeature];
            node = value <= node.Threshold ? node.Left : node.Right!;
        }

        return node.LeafValue ?? 0.0;
    }

    private sealed class ModelFile
    {
        [JsonPropertyName("version")]
        public string? Version { get; set; }

        [JsonPropertyName("trees")]
        public List<TreeNode>? Trees { get; set; }
    }

    private sealed class TreeNode
    {
        [JsonPropertyName("leaf_value")]
        public double? LeafValue { get; set; }

        [JsonPropertyName("split_feature")]
        public int SplitFeature { get; set; }

        [JsonPropertyName("threshold")]
        public double Threshold { get; set; }

        [JsonPropertyName("left")]
        public TreeNode? Left { get; set; }

        [JsonPropertyName("right")]
        public TreeNode? Right { get; set; }
    }
}

/// <summary>MurmurHash3 x86 32-bit, matching sklearn's murmurhash3_32(seed=0).</summary>
public static class MurmurHash3
{
    public static int Hash32(ReadOnlySpan<byte> data, uint seed)
    {
        const uint c1 = 0xcc9e2d51;
        const uint c2 = 0x1b873593;

        var h1 = seed;
        var blockCount = data.Length / 4;
        for (var i = 0; i < blockCount; i++)
        {
            var offset = i * 4;
            var k1 = (uint)(data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16 | data[offset + 3] << 24);
            k1 *= c1;
            k1 = (k1 << 15) | (k1 >> 17);
            k1 *= c2;
            h1 ^= k1;
            h1 = (h1 << 13) | (h1 >> 19);
            h1 = h1 * 5 + 0xe6546b64;
        }

        uint tail = 0;
        var remainder = data.Length & 3;
        var tailOffset = blockCount * 4;
        if (remainder == 3)
        {
            tail ^= (uint)data[tailOffset + 2] << 16;
        }

        if (remainder >= 2)
        {
            tail ^= (uint)data[tailOffset + 1] << 8;
        }

        if (remainder >= 1)
        {
            tail ^= data[tailOffset];
            tail *= c1;
            tail = (tail << 15) | (tail >> 17);
            tail *= c2;
            h1 ^= tail;
        }

        h1 ^= (uint)data.Length;
        h1 ^= h1 >> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return unchecked((int)h1);
    }
}
