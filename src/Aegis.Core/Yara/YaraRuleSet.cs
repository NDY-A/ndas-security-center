using System.Text;
using System.Text.RegularExpressions;
using Aegis.Core.Models;

namespace Aegis.Core.Yara;

public sealed class YaraRuleSet
{
    public static YaraRuleSet Empty { get; } = new(Array.Empty<YaraRule>(), 0, Array.Empty<string>());

    private const int MaxDiagnostics = 40;
    private const long MaxRuleFileBytes = 16L * 1024 * 1024;

    private readonly CompiledRule[] _rules;
    private readonly YaraStringDef[] _stringDefs;
    private readonly AcAutomaton _filterAutomaton;

    private YaraRuleSet(IReadOnlyList<YaraRule> rules, int skipped, IReadOnlyList<string> warnings)
    {
        SkippedCount = skipped;
        Warnings = warnings;

        var compiledRules = new List<CompiledRule>(rules.Count);
        var definitions = new List<YaraStringDef>();
        var filterAutomaton = new AcAutomaton();

        foreach (var rule in rules)
        {
            var indices = new int[rule.Strings.Count];
            var candidates = new List<(int GlobalIndex, int Length)>();
            for (var index = 0; index < rule.Strings.Count; index++)
            {
                var definition = rule.Strings[index];
                var globalIndex = definitions.Count;
                definitions.Add(definition);
                indices[index] = globalIndex;

                if (definition.Kind == YaraStringKind.Text && !string.IsNullOrEmpty(definition.Text))
                {
                    candidates.Add((globalIndex, definition.Text.Length));
                }
                else if (definition.Literal is { Length: >= 4 } literal)
                {
                    candidates.Add((globalIndex, literal.Length));
                }
            }

            var anchors = candidates
                .OrderByDescending(candidate => candidate.Length)
                .Take(2)
                .Select(candidate => candidate.GlobalIndex)
                .ToArray();

            foreach (var anchor in anchors)
            {
                var definition = definitions[anchor];
                if (definition.Kind == YaraStringKind.Text)
                {
                    var asciiBytes = LowerAsciiBytes(Encoding.UTF8.GetBytes(definition.Text!));
                    var wideBytes = definition.Wide ? LowerAsciiBytes(Encoding.Unicode.GetBytes(definition.Text!)) : null;

                    if (definition.Ascii)
                    {
                        filterAutomaton.Add(Latin1(asciiBytes), anchor, definition.Fullword, wide: false);
                    }

                    if (wideBytes is not null)
                    {
                        filterAutomaton.Add(Latin1(wideBytes), anchor, definition.Fullword, wide: true);
                    }
                }
                else if (definition.Literal is { } literal)
                {
                    filterAutomaton.Add(Latin1(LowerAsciiBytes(literal)), anchor, fullword: false, wide: false);
                }
            }

            compiledRules.Add(new CompiledRule(rule, indices, anchors));
        }

        filterAutomaton.Build();
        _rules = compiledRules.ToArray();
        _stringDefs = definitions.ToArray();
        _filterAutomaton = filterAutomaton;
    }

    public int FilterNodeCount => _filterAutomaton.NodeCount;

    public int RuleCount => _rules.Length;

    public int StringCount => _stringDefs.Length;

    public int SkippedCount { get; }

    public IReadOnlyList<string> Warnings { get; }

    public static YaraRuleSet Parse(string text, string source)
    {
        var rules = YaraParser.Parse(text, source, out var skipped, out var warnings);
        return new YaraRuleSet(rules, skipped, warnings);
    }

    public static YaraRuleSet LoadDirectory(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return Empty;
        }

        var rules = new List<YaraRule>();
        var warnings = new List<string>();
        var skipped = 0;
        var files = Directory.EnumerateFiles(directory, "*.yar", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(directory, "*.yara", SearchOption.TopDirectoryOnly))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            try
            {
                var info = new FileInfo(file);
                if (!info.Exists || info.Length == 0)
                {
                    continue;
                }

                if (info.Length > MaxRuleFileBytes)
                {
                    warnings.Add($"{Path.GetFileName(file)}: 规则文件超过大小限制，已跳过。");
                    continue;
                }

                var text = File.ReadAllText(file, Encoding.UTF8);
                var parsed = YaraParser.Parse(text, Path.GetFileName(file), out var fileSkipped, out var fileWarnings);
                rules.AddRange(parsed);
                skipped += fileSkipped;
                foreach (var warning in fileWarnings)
                {
                    if (warnings.Count < MaxDiagnostics)
                    {
                        warnings.Add(warning);
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DecoderFallbackException)
            {
                warnings.Add($"{Path.GetFileName(file)}: 读取失败（{exception.GetType().Name}）。");
            }
        }

        return new YaraRuleSet(rules, skipped, warnings);
    }

    public YaraScanResult Scan(byte[] data, PeFileInfo? peInfo = null)
    {
        if (_rules.Length == 0 || data.Length == 0)
        {
            return YaraScanResult.Empty;
        }

        var text = Encoding.Latin1.GetString(data);
        var state = new YaraScanState(_stringDefs, text, data);
        var timer = System.Diagnostics.Stopwatch.StartNew();
        if (_filterAutomaton.HasPatterns)
        {
            var lowerText = LowerAsciiText(text);
            state.LowerText = lowerText;
            _filterAutomaton.Scan(lowerText, state);
        }

        var acMilliseconds = timer.ElapsedMilliseconds;
        timer.Restart();

        var pe = YaraPeContext.Create(data, peInfo);
        var matches = new List<YaraRuleMatch>();
        var candidates = 0;
        foreach (var compiled in _rules)
        {
            // The longest text literals act as per-rule fingerprints: when neither appears,
            // skip the rule before paying for hex/regex evaluation. Rules made up only of
            // hex/regex strings have no cheap fingerprint and are skipped to keep per-file
            // scan time bounded; PE-only rules without strings are still evaluated.
            if (compiled.Rule.Strings.Count > 0)
            {
                if (compiled.AnchorGlobals.Length == 0 || !AnyTextMatch(state, compiled.AnchorGlobals))
                {
                    continue;
                }
            }

            candidates++;
            try
            {
                var context = new RuleContext(state, compiled, pe);
                if (!YaraEvaluator.Evaluate(compiled.Rule.Condition, context))
                {
                    continue;
                }

                var matchedStrings = new List<string>();
                foreach (var definition in compiled.Rule.Strings)
                {
                    if (context.IsMatch(definition.Index))
                    {
                        matchedStrings.Add(definition.Identifier);
                        if (matchedStrings.Count >= 8)
                        {
                            break;
                        }
                    }
                }

                matches.Add(new YaraRuleMatch(compiled.Rule, matchedStrings));
            }
            catch (Exception exception) when (exception is RegexMatchTimeoutException or ArgumentException or IndexOutOfRangeException)
            {
                // A rule that fails to evaluate is treated as non-matching; one bad rule must not abort the scan.
            }
        }

        return new YaraScanResult(matches, _rules.Length, candidates, state.RegexEvaluations, acMilliseconds, timer.ElapsedMilliseconds);
    }

    private static string Latin1(byte[] bytes)
    {
        return Encoding.Latin1.GetString(bytes);
    }

    private static byte[] LowerAsciiBytes(byte[] bytes)
    {
        var copy = new byte[bytes.Length];
        for (var index = 0; index < bytes.Length; index++)
        {
            var value = bytes[index];
            copy[index] = value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
        }

        return copy;
    }

    private static string LowerAsciiText(string text)
    {
        var characters = text.ToCharArray();
        for (var index = 0; index < characters.Length; index++)
        {
            var value = characters[index];
            if (value is >= 'A' and <= 'Z')
            {
                characters[index] = (char)(value + 32);
            }
        }

        return new string(characters);
    }

    private static bool IsWordCharacter(char value) => char.IsAsciiLetterOrDigit(value) || value == '_';

    private static bool AnyTextMatch(YaraScanState state, int[] textGlobals)
    {
        foreach (var globalIndex in textGlobals)
        {
            if (state.AcHit(globalIndex))
            {
                return true;
            }
        }

        return false;
    }

    private sealed record CompiledRule(YaraRule Rule, int[] GlobalIndices, int[] AnchorGlobals);

    internal sealed class YaraScanState
    {
        private readonly YaraStringDef[] _definitions;
        private readonly bool[] _acHits;
        private readonly int[] _counts;
        private readonly long[] _offsets;
        private readonly long[] _lengths;
        private readonly bool[] _regexEvaluated;

        public YaraScanState(YaraStringDef[] definitions, string text, byte[] data)
        {
            _definitions = definitions;
            _acHits = new bool[definitions.Length];
            _counts = new int[definitions.Length];
            _offsets = new long[definitions.Length];
            _lengths = new long[definitions.Length];
            _regexEvaluated = new bool[definitions.Length];
            Text = text;
            Data = data;
        }

        public bool AcHit(int globalIndex) => _acHits[globalIndex];

        public string Text { get; }

        public string? LowerText { get; set; }

        public byte[] Data { get; }

        public int RegexEvaluations { get; private set; }

        public void Record(int globalIndex, int end, int length, bool fullword, bool wide, string view)
        {
            if (fullword)
            {
                var start = end - length + 1;
                var beforeIndex = wide ? start - 2 : start - 1;
                var afterIndex = wide ? end + 2 : end + 1;
                if (beforeIndex >= 0 && IsWordCharacter(view[beforeIndex]))
                {
                    return;
                }

                if (afterIndex < view.Length && IsWordCharacter(view[afterIndex]))
                {
                    return;
                }
            }

            _acHits[globalIndex] = true;
        }

        public bool IsMatch(int globalIndex) => GetCount(globalIndex) > 0;

        public long GetCount(int globalIndex)
        {
            EnsureEvaluated(globalIndex);
            return _counts[globalIndex];
        }

        public long GetOffset(int globalIndex)
        {
            EnsureEvaluated(globalIndex);
            return _offsets[globalIndex];
        }

        public long GetLength(int globalIndex)
        {
            EnsureEvaluated(globalIndex);
            return _lengths[globalIndex];
        }

        private void EnsureEvaluated(int globalIndex)
        {
            if (_regexEvaluated[globalIndex])
            {
                return;
            }

            _regexEvaluated[globalIndex] = true;
            var definition = _definitions[globalIndex];
            if (definition.Kind == YaraStringKind.Text)
            {
                MatchTextLazily(globalIndex, definition);
                return;
            }

            if (definition.CompiledRegex is null)
            {
                return;
            }

            RegexEvaluations++;

            try
            {
                var match = definition.CompiledRegex.Match(Text);
                if (!match.Success)
                {
                    return;
                }

                _offsets[globalIndex] = match.Index;
                _lengths[globalIndex] = match.Length;
                var count = 1;
                while (count < 64)
                {
                    var next = match.NextMatch();
                    if (!next.Success)
                    {
                        break;
                    }

                    match = next;
                    count++;
                }

                _counts[globalIndex] = count;
            }
            catch (RegexMatchTimeoutException)
            {
                // Treat a timed-out regex as non-matching for this file.
            }
        }

        private void MatchTextLazily(int globalIndex, YaraStringDef definition)
        {
            if (string.IsNullOrEmpty(definition.Text))
            {
                return;
            }

            int? firstOffset = null;
            var firstLength = 0;
            var count = 0;

            void Search(string haystack, string needle, bool fullword, bool wide)
            {
                if (needle.Length == 0)
                {
                    return;
                }

                var start = 0;
                while (count < 64 && start <= haystack.Length - needle.Length)
                {
                    var index = haystack.IndexOf(needle, start, StringComparison.Ordinal);
                    if (index < 0)
                    {
                        break;
                    }

                    if (!fullword || IsFullwordBoundary(haystack, index, needle.Length, wide))
                    {
                        firstOffset ??= index;
                        if (firstOffset == index && firstLength == 0)
                        {
                            firstLength = needle.Length;
                        }

                        count++;
                    }

                    start = index + 1;
                }
            }

            var asciiNeedle = Latin1TextPattern(definition.Text);
            var wideNeedle = definition.Wide ? WideTextPattern(definition.Text) : null;

            if (definition.Ascii)
            {
                if (definition.Nocase)
                {
                    var lower = LowerText ??= LowerAsciiText(Text);
                    Search(lower, LowerAsciiText(asciiNeedle), definition.Fullword, wide: false);
                }
                else
                {
                    Search(Text, asciiNeedle, definition.Fullword, wide: false);
                }
            }

            if (wideNeedle is not null)
            {
                if (definition.Nocase)
                {
                    var lower = LowerText ??= LowerAsciiText(Text);
                    Search(lower, LowerAsciiText(wideNeedle), definition.Fullword, wide: true);
                }
                else
                {
                    Search(Text, wideNeedle, definition.Fullword, wide: true);
                }
            }

            if (count > 0)
            {
                _counts[globalIndex] = count;
                _offsets[globalIndex] = firstOffset ?? 0;
                _lengths[globalIndex] = firstLength;
            }
        }

        private static bool IsFullwordBoundary(string haystack, int index, int length, bool wide)
        {
            var before = wide ? index - 2 : index - 1;
            var after = index + length;
            if (before >= 0 && IsWordCharacter(haystack[before]))
            {
                return false;
            }

            return after >= haystack.Length || !IsWordCharacter(haystack[after]);
        }
    }

    private static string Latin1TextPattern(string value) => Encoding.Latin1.GetString(Encoding.UTF8.GetBytes(value));

    private static string WideTextPattern(string value) => Encoding.Latin1.GetString(Encoding.Unicode.GetBytes(value));

    private sealed class RuleContext : IYaraEvaluationContext
    {
        private readonly YaraScanState _state;
        private readonly CompiledRule _rule;
        private readonly YaraPeContext? _pe;

        public RuleContext(YaraScanState state, CompiledRule rule, YaraPeContext? pe)
        {
            _state = state;
            _rule = rule;
            _pe = pe;
        }

        public long FileSize => _state.Data.Length;

        public byte[] Data => _state.Data;

        public bool IsMatch(int stringIndex)
        {
            return _state.IsMatch(_rule.GlobalIndices[stringIndex]);
        }

        public long GetMatchCount(int stringIndex)
        {
            return _state.GetCount(_rule.GlobalIndices[stringIndex]);
        }

        public long? GetMatchOffset(int stringIndex)
        {
            var globalIndex = _rule.GlobalIndices[stringIndex];
            return _state.GetCount(globalIndex) > 0 ? _state.GetOffset(globalIndex) : null;
        }

        public long? GetMatchLength(int stringIndex)
        {
            var globalIndex = _rule.GlobalIndices[stringIndex];
            return _state.GetCount(globalIndex) > 0 ? _state.GetLength(globalIndex) : null;
        }

        public long ReadInteger(int width, long offset, bool bigEndian)
        {
            if (offset < 0 || width is <= 0 or > 8 || offset + width > _state.Data.Length)
            {
                return 0;
            }

            ulong value = 0;
            for (var index = 0; index < width; index++)
            {
                var position = bigEndian ? offset + width - 1 - index : offset + index;
                value |= (ulong)_state.Data[(int)position] << (8 * index);
            }

            return unchecked((long)value);
        }

        public object? Call(string name, IReadOnlyList<object?> arguments)
        {
            switch (name)
            {
                case "uint8":
                    return ReadInteger(1, ToLong(arguments, 0), bigEndian: false);
                case "uint16":
                    return ReadInteger(2, ToLong(arguments, 0), bigEndian: false);
                case "uint32":
                    return ReadInteger(4, ToLong(arguments, 0), bigEndian: false);
                case "int8":
                    return SignExtend(ReadInteger(1, ToLong(arguments, 0), bigEndian: false), 1);
                case "int16":
                    return SignExtend(ReadInteger(2, ToLong(arguments, 0), bigEndian: false), 2);
                case "int32":
                    return SignExtend(ReadInteger(4, ToLong(arguments, 0), bigEndian: false), 4);
                case "pe.MACHINE_I386":
                    return 0x14cL;
                case "pe.MACHINE_AMD64":
                    return 0x8664L;
                case "pe.MACHINE_ARM":
                    return 0x1c0L;
                case "pe.MACHINE_ARM64":
                    return 0xAA64L;
                case "pe.SUBSYSTEM_WINDOWS_GUI":
                    return 2L;
                case "pe.SUBSYSTEM_WINDOWS_CUI":
                    return 3L;
                case "pe.SUBSYSTEM_NATIVE":
                    return 1L;
                case "pe.is_pe":
                    return _pe is null ? 0L : 1L;
                case "pe.number_of_sections":
                    return _pe?.NumberOfSections ?? 0L;
                case "pe.entry_point":
                    return _pe?.EntryPoint ?? 0L;
                case "pe.machine":
                    return _pe?.Machine ?? 0L;
                case "pe.subsystem":
                    return _pe?.Subsystem ?? 0L;
                case "pe.is_dll":
                    return _pe is { IsDll: true } ? 1L : 0L;
                case "pe.imports":
                    return CheckImports(arguments);
                default:
                    return null;
            }
        }

        private long CheckImports(IReadOnlyList<object?> arguments)
        {
            if (_pe is null || arguments.Count == 0)
            {
                return 0L;
            }

            var dll = arguments[0] as string;
            if (string.IsNullOrWhiteSpace(dll))
            {
                return 0L;
            }

            if (arguments.Count == 1)
            {
                return _pe.ImportedDlls.Any(value => string.Equals(value, dll, StringComparison.OrdinalIgnoreCase)) ? 1L : 0L;
            }

            var function = arguments[1] as string;
            if (string.IsNullOrWhiteSpace(function))
            {
                return 0L;
            }

            var dllKnown = _pe.ImportedDlls.Any(value => string.Equals(value, dll, StringComparison.OrdinalIgnoreCase));
            var functionKnown = _pe.ImportedFunctions.Any(value => string.Equals(value, function, StringComparison.OrdinalIgnoreCase));
            return dllKnown && functionKnown ? 1L : 0L;
        }

        private static long ToLong(IReadOnlyList<object?> arguments, int index)
        {
            if (index >= arguments.Count)
            {
                return -1;
            }

            return arguments[index] switch
            {
                long value => value,
                bool boolean => boolean ? 1 : 0,
                _ => -1
            };
        }

        private static long SignExtend(long value, int width)
        {
            var shift = 64 - width * 8;
            return (value << shift) >> shift;
        }
    }
}

internal sealed class AcAutomaton
{
    private readonly List<int> _firstEdge = new() { -1 };
    private readonly List<char> _edgeCharacter = new();
    private readonly List<int> _edgeTarget = new();
    private readonly List<int> _edgeNext = new();
    private readonly List<int> _outputs = new() { -1 };
    private readonly List<int> _outputString = new();
    private readonly List<int> _outputLength = new();
    private readonly List<bool> _outputFullword = new();
    private readonly List<bool> _outputWide = new();
    private readonly List<int> _outputNext = new();
    private int[] _failure = Array.Empty<int>();
    private int[] _outputLink = Array.Empty<int>();
    private int[]? _goto;
    private ushort[]? _gotoShort;
    private bool _built;

    public bool HasPatterns => _outputString.Count > 0;

    public int NodeCount => _firstEdge.Count;

    public void Add(string pattern, int stringIndex, bool fullword, bool wide)
    {
        if (pattern.Length == 0)
        {
            return;
        }

        var node = 0;
        foreach (var character in pattern)
        {
            node = GetOrAddTransition(node, character);
        }

        var outputIndex = _outputString.Count;
        _outputString.Add(stringIndex);
        _outputLength.Add(pattern.Length);
        _outputFullword.Add(fullword);
        _outputWide.Add(wide);
        _outputNext.Add(_outputs[node]);
        _outputs[node] = outputIndex;
    }

    private int GetOrAddTransition(int node, char character)
    {
        var edge = _firstEdge[node];
        while (edge >= 0)
        {
            if (_edgeCharacter[edge] == character)
            {
                return _edgeTarget[edge];
            }

            edge = _edgeNext[edge];
        }

        var target = _firstEdge.Count;
        _firstEdge.Add(-1);
        _outputs.Add(-1);

        var newEdge = _edgeCharacter.Count;
        _edgeCharacter.Add(character);
        _edgeTarget.Add(target);
        _edgeNext.Add(_firstEdge[node]);
        _firstEdge[node] = newEdge;
        return target;
    }

    public void Build()
    {
        if (_built || !HasPatterns)
        {
            _built = true;
            return;
        }

        var count = _firstEdge.Count;
        _failure = new int[count];
        _outputLink = new int[count];
        Array.Fill(_outputLink, -1);
        var queue = new Queue<int>();

        for (var edge = _firstEdge[0]; edge >= 0; edge = _edgeNext[edge])
        {
            var child = _edgeTarget[edge];
            _failure[child] = 0;
            queue.Enqueue(child);
        }

        while (queue.Count > 0)
        {
            var node = queue.Dequeue();
            for (var edge = _firstEdge[node]; edge >= 0; edge = _edgeNext[edge])
            {
                var character = _edgeCharacter[edge];
                var child = _edgeTarget[edge];
                var fallback = _failure[node];
                var transition = Transition(fallback, character);
                while (fallback != 0 && transition < 0)
                {
                    fallback = _failure[fallback];
                    transition = Transition(fallback, character);
                }

                _failure[child] = transition >= 0 ? transition : 0;
                _outputLink[child] = _outputs[_failure[child]] >= 0 ? _failure[child] : _outputLink[_failure[child]];
                queue.Enqueue(child);
            }
        }

        var denseQueue = new Queue<int>();
        for (var edge = _firstEdge[0]; edge >= 0; edge = _edgeNext[edge])
        {
            denseQueue.Enqueue(_edgeTarget[edge]);
        }

        if (count <= ushort.MaxValue)
        {
            var table = new ushort[count * 256];
            for (var edge = _firstEdge[0]; edge >= 0; edge = _edgeNext[edge])
            {
                table[_edgeCharacter[edge]] = (ushort)_edgeTarget[edge];
            }

            while (denseQueue.Count > 0)
            {
                var node = denseQueue.Dequeue();
                var row = node * 256;
                var failRow = _failure[node] * 256;
                Array.Copy(table, failRow, table, row, 256);
                for (var edge = _firstEdge[node]; edge >= 0; edge = _edgeNext[edge])
                {
                    table[row + _edgeCharacter[edge]] = (ushort)_edgeTarget[edge];
                }

                for (var edge = _firstEdge[node]; edge >= 0; edge = _edgeNext[edge])
                {
                    denseQueue.Enqueue(_edgeTarget[edge]);
                }
            }

            _gotoShort = table;
        }
        else
        {
            var table = new int[count * 256];
            for (var edge = _firstEdge[0]; edge >= 0; edge = _edgeNext[edge])
            {
                table[_edgeCharacter[edge]] = _edgeTarget[edge];
            }

            while (denseQueue.Count > 0)
            {
                var node = denseQueue.Dequeue();
                var row = node * 256;
                var failRow = _failure[node] * 256;
                Array.Copy(table, failRow, table, row, 256);
                for (var edge = _firstEdge[node]; edge >= 0; edge = _edgeNext[edge])
                {
                    table[row + _edgeCharacter[edge]] = _edgeTarget[edge];
                }

                for (var edge = _firstEdge[node]; edge >= 0; edge = _edgeNext[edge])
                {
                    denseQueue.Enqueue(_edgeTarget[edge]);
                }
            }

            _goto = table;
        }

        _built = true;
    }

    private int Transition(int node, int character)
    {
        var edge = _firstEdge[node];
        while (edge >= 0)
        {
            if (_edgeCharacter[edge] == character)
            {
                return _edgeTarget[edge];
            }

            edge = _edgeNext[edge];
        }

        return -1;
    }

    public void Scan(string text, YaraRuleSet.YaraScanState state)
    {
        if (!_built || !HasPatterns)
        {
            return;
        }

        var node = 0;
        var table = _gotoShort;
        var wideTable = _goto;
        for (var index = 0; index < text.Length; index++)
        {
            node = table is not null
                ? table[(node << 8) | text[index]]
                : wideTable![(node << 8) | text[index]];

            for (var outputNode = node; outputNode != -1; outputNode = _outputLink[outputNode])
            {
                for (var output = _outputs[outputNode]; output >= 0; output = _outputNext[output])
                {
                    state.Record(_outputString[output], index, _outputLength[output], _outputFullword[output], _outputWide[output], text);
                }
            }
        }
    }
}

internal sealed class YaraPeContext
{
    private YaraPeContext()
    {
    }

    public int NumberOfSections { get; private init; }

    public long EntryPoint { get; private init; }

    public int Machine { get; private init; }

    public int Subsystem { get; private init; }

    public bool IsDll { get; private init; }

    public IReadOnlyList<string> ImportedDlls { get; private init; } = Array.Empty<string>();

    public IReadOnlyList<string> ImportedFunctions { get; private init; } = Array.Empty<string>();

    public static YaraPeContext? Create(byte[] data, PeFileInfo? info)
    {
        if (data.Length < 64 || data[0] != 'M' || data[1] != 'Z')
        {
            return null;
        }

        var peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 24 > data.Length ||
            data[peOffset] != 'P' || data[peOffset + 1] != 'E' ||
            data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
        {
            return null;
        }

        var machine = BitConverter.ToUInt16(data, peOffset + 4);
        var sections = BitConverter.ToUInt16(data, peOffset + 6);
        var characteristics = BitConverter.ToUInt16(data, peOffset + 22);
        var optional = peOffset + 24;
        long entryPoint = 0;
        var subsystem = 0;
        if (optional + 70 <= data.Length)
        {
            entryPoint = BitConverter.ToUInt32(data, optional + 16);
            subsystem = BitConverter.ToUInt16(data, optional + 68);
        }

        return new YaraPeContext
        {
            NumberOfSections = sections,
            EntryPoint = entryPoint,
            Machine = machine,
            Subsystem = subsystem,
            IsDll = (characteristics & 0x2000) != 0,
            ImportedDlls = info?.ImportedDlls ?? Array.Empty<string>(),
            ImportedFunctions = info?.ImportedFunctions ?? Array.Empty<string>()
        };
    }
}
