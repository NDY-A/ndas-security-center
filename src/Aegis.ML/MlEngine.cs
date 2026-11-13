namespace Aegis.ML;

public static class MlEngine
{
    private static readonly object Sync = new();
    private static bool _attempted;
    private static bool _available;
    private static string _status = "尚未初始化";

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
                return _available ? NativeMethods.ModelVersion() : string.Empty;
            }
        }
    }

    public static bool TryScore(string path, out float probability, out string? error)
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

            try
            {
                var rc = NativeMethods.AegisMlScoreFile(path, out probability);
                if (rc < 0)
                {
                    error = "ML 评分失败：" + NativeMethods.LastError();
                    return false;
                }

                return true;
            }
            catch (Exception exception) when (exception is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
            {
                _available = false;
                _status = "原生组件不可用：" + exception.GetType().Name;
                error = _status;
                return false;
            }
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
                _status = "未找到模型文件（ML\\pe-ml.onnx）";
                return;
            }

            var rc = NativeMethods.AegisMlLoadModel(modelPath);
            if (rc != 0)
            {
                _status = "模型加载失败：" + NativeMethods.LastError();
                return;
            }

            _available = true;
            _status = "已加载 " + NativeMethods.ModelVersion();
        }
        catch (Exception exception) when (exception is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
        {
            _status = "原生组件不可用：" + exception.GetType().Name;
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
            Path.Combine(baseDirectory, "ML", "pe-ml.onnx"),
            Path.Combine(baseDirectory, "pe-ml.onnx"),
            Path.Combine(baseDirectory, "Models", "pe-ml.onnx")
        };
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        var overridePath = Environment.GetEnvironmentVariable("NDAS_ML_MODEL");
        if (!string.IsNullOrWhiteSpace(overridePath) && File.Exists(overridePath))
        {
            return overridePath;
        }

        return null;
    }
}
