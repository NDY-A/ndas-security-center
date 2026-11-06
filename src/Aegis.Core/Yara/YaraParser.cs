using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Aegis.Core.Yara;

public sealed class YaraParseException : Exception
{
    public YaraParseException(string message) : base(message)
    {
    }
}

public static class YaraParser
{
    private static readonly RegexOptions ConditionRegexOptions = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    public static IReadOnlyList<YaraRule> Parse(string text, string source, out int skipped, out IReadOnlyList<string> warnings)
    {
        var rules = new List<YaraRule>();
        var localWarnings = new List<string>();
        skipped = 0;

        foreach (var block in ExtractBlocks(text))
        {
            try
            {
                var parser = new RuleParser(block.Text, source, block.Line);
                var rule = parser.ParseRule();
                if (rule is not null)
                {
                    rules.Add(rule);
                }
            }
            catch (Exception exception) when (exception is YaraParseException or ArgumentException or RegexMatchTimeoutException)
            {
                skipped++;
                if (localWarnings.Count < 40)
                {
                    localWarnings.Add(exception.Message);
                }
            }
        }

        warnings = localWarnings;
        return rules;
    }

    private sealed record RuleBlock(string Text, int Line);

    private static IEnumerable<RuleBlock> ExtractBlocks(string text)
    {
        var index = 0;
        var line = 1;
        var length = text.Length;

        while (index < length)
        {
            var character = text[index];
            if (character == '\n')
            {
                line++;
                index++;
                continue;
            }

            if (character is '"' or '\'')
            {
                index = SkipQuoted(text, index, line);
                continue;
            }

            if (character == '/' && index + 1 < length && text[index + 1] == '/')
            {
                index = SkipLineComment(text, index);
                continue;
            }

            if (character == '/' && index + 1 < length && text[index + 1] == '*')
            {
                (index, line) = SkipBlockComment(text, index, line);
                continue;
            }

            if (IsIdentifierStart(character) && IsWordAt(text, index, "rule"))
            {
                var startLine = line;
                var blockStart = index;
                var before = FindPreviousWord(text, index);
                if (before is not null &&
                    (before.Value.Word.Equals("private", StringComparison.Ordinal) ||
                     before.Value.Word.Equals("global", StringComparison.Ordinal)))
                {
                    blockStart = before.Value.Start;
                }

                var end = FindBlockEnd(text, index, ref line);
                if (end > index)
                {
                    yield return new RuleBlock(text[blockStart..end], startLine);
                    index = end;
                    continue;
                }
            }

            index++;
        }
    }

    private static int FindBlockEnd(string text, int start, ref int line)
    {
        var index = start;
        var depth = 0;
        var seenBrace = false;
        var length = text.Length;

        while (index < length)
        {
            var character = text[index];
            if (character == '\n')
            {
                line++;
                index++;
                continue;
            }

            if (character == '/' && index + 1 < length && text[index + 1] == '/')
            {
                index = SkipLineComment(text, index);
                continue;
            }

            if (character == '/' && index + 1 < length && text[index + 1] == '*')
            {
                (index, line) = SkipBlockComment(text, index, line);
                continue;
            }

            if (character == '"')
            {
                index = SkipQuoted(text, index, line);
                continue;
            }

            if (character == '/' && IsRegexStart(text, index))
            {
                index = SkipRegex(text, index, line);
                continue;
            }

            if (character == '{')
            {
                depth++;
                seenBrace = true;
            }
            else if (character == '}')
            {
                depth--;
                if (seenBrace && depth == 0)
                {
                    return index + 1;
                }

                if (depth < 0)
                {
                    return index;
                }
            }

            index++;
        }

        return -1;
    }

    private static int SkipQuoted(string text, int index, int line)
    {
        var quote = text[index];
        index++;
        while (index < text.Length)
        {
            if (text[index] == '\\')
            {
                index += 2;
                continue;
            }

            if (text[index] == quote)
            {
                return index + 1;
            }

            index++;
        }

        return text.Length;
    }

    private static int SkipRegex(string text, int index, int line)
    {
        index++;
        while (index < text.Length)
        {
            if (text[index] == '\\')
            {
                index += 2;
                continue;
            }

            if (text[index] == '/')
            {
                return index + 1;
            }

            index++;
        }

        return text.Length;
    }

    private static int SkipLineComment(string text, int index)
    {
        while (index < text.Length && text[index] != '\n')
        {
            index++;
        }

        return index;
    }

    private static (int Index, int Line) SkipBlockComment(string text, int index, int line)
    {
        index += 2;
        while (index + 1 < text.Length)
        {
            if (text[index] == '\n')
            {
                line++;
            }

            if (text[index] == '*' && text[index + 1] == '/')
            {
                return (index + 2, line);
            }

            index++;
        }

        return (text.Length, line);
    }

    private static bool IsRegexStart(string text, int index)
    {
        var cursor = index - 1;
        while (cursor >= 0 && char.IsWhiteSpace(text[cursor]))
        {
            cursor--;
        }

        if (cursor < 0)
        {
            return false;
        }

        var character = text[cursor];
        if (character is '=' or ',' or '(' or '[' or '!' or '~' or ':' or '|')
        {
            return true;
        }

        if (!IsIdentifierPart(character))
        {
            return false;
        }

        var wordStart = cursor;
        while (wordStart > 0 && IsIdentifierPart(text[wordStart - 1]))
        {
            wordStart--;
        }

        return text.AsSpan(wordStart, cursor - wordStart + 1).SequenceEqual("matches");
    }

    private static (string Word, int Start)? FindPreviousWord(string text, int index)
    {
        var cursor = index - 1;
        while (cursor >= 0 && char.IsWhiteSpace(text[cursor]))
        {
            cursor--;
        }

        if (cursor < 0 || !IsIdentifierPart(text[cursor]))
        {
            return null;
        }

        var end = cursor;
        while (cursor > 0 && IsIdentifierPart(text[cursor - 1]))
        {
            cursor--;
        }

        return (text[cursor..(end + 1)], cursor);
    }

    private static bool IsWordAt(string text, int index, string word)
    {
        if (index + word.Length > text.Length)
        {
            return false;
        }

        if (!text.AsSpan(index, word.Length).SequenceEqual(word))
        {
            return false;
        }

        if (index > 0 && IsIdentifierPart(text[index - 1]))
        {
            return false;
        }

        var after = index + word.Length;
        return after >= text.Length || !IsIdentifierPart(text[after]);
    }

    private static bool IsIdentifierStart(char value) => char.IsAsciiLetter(value) || value == '_';

    private static bool IsIdentifierPart(char value) => char.IsAsciiLetterOrDigit(value) || value == '_';

    private enum TokenKind
    {
        End,
        Identifier,
        String,
        Number,
        Reference,
        Punct
    }

    private readonly record struct Token(TokenKind Kind, string Text, long Number, int Position, string? Raw = null);

    private sealed class RuleParser
    {
        private static readonly HashSet<string> SupportedCalls = new(StringComparer.Ordinal)
        {
            "uint8", "uint16", "uint32", "int8", "int16", "int32",
            "pe.is_pe", "pe.number_of_sections", "pe.entry_point", "pe.machine",
            "pe.subsystem", "pe.is_dll", "pe.imports"
        };

        private static readonly HashSet<string> SupportedConstants = new(StringComparer.Ordinal)
        {
            "pe.MACHINE_I386", "pe.MACHINE_AMD64", "pe.MACHINE_ARM", "pe.MACHINE_ARM64",
            "pe.SUBSYSTEM_WINDOWS_GUI", "pe.SUBSYSTEM_WINDOWS_CUI", "pe.SUBSYSTEM_NATIVE"
        };

        private readonly string _text;
        private readonly string _source;
        private readonly int _line;
        private int _position;
        private Token? _peeked;
        private readonly List<YaraStringDef> _strings = new();

        public RuleParser(string text, string source, int line)
        {
            _text = text;
            _source = source;
            _line = line;
        }

        public YaraRule? ParseRule()
        {
            var isPrivateOrGlobal = false;
            if (Peek().Kind == TokenKind.Identifier && (Peek().Text == "private" || Peek().Text == "global"))
            {
                isPrivateOrGlobal = true;
                Next();
            }

            if (Next().Text != "rule")
            {
                throw Error("缺少 rule 关键字");
            }

            var nameToken = Next();
            if (nameToken.Kind != TokenKind.Identifier)
            {
                throw Error("缺少规则名称");
            }

            var name = nameToken.Text;
            var tags = new List<string>();
            if (Peek().Kind == TokenKind.Punct && Peek().Text == ":")
            {
                Next();
                while (Peek().Kind == TokenKind.Identifier)
                {
                    tags.Add(Next().Text);
                }
            }

            ExpectPunct("{");
            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            YaraExpression? condition = null;

            while (true)
            {
                var token = Peek();
                if (token.Kind == TokenKind.Punct && token.Text == "}")
                {
                    Next();
                    break;
                }

                if (token.Kind != TokenKind.Identifier)
                {
                    throw Error("无法识别的规则段落");
                }

                var section = Next().Text;
                ExpectPunct(":");
                switch (section.ToLowerInvariant())
                {
                    case "meta":
                        ParseMeta(meta);
                        break;
                    case "strings":
                        ParseStrings();
                        break;
                    case "condition":
                        condition = ParseExpression();
                        break;
                    default:
                        throw Error("不支持的规则段落 " + section);
                }
            }

            if (condition is null)
            {
                throw Error("规则缺少 condition");
            }

            if (isPrivateOrGlobal)
            {
                return null;
            }

            return new YaraRule
            {
                Identifier = name,
                Tags = tags,
                Meta = meta,
                Strings = _strings,
                Condition = condition,
                Source = _source
            };
        }

        private void ParseMeta(Dictionary<string, string> meta)
        {
            while (true)
            {
                var next = Peek();
                if (next.Kind != TokenKind.Identifier || next.Text is "strings" or "condition")
                {
                    break;
                }

                var key = Next().Text;
                ExpectPunct("=");
                var token = Next();
                switch (token.Kind)
                {
                    case TokenKind.String:
                        meta[key] = token.Text;
                        break;
                    case TokenKind.Number:
                        meta[key] = token.Number.ToString(CultureInfo.InvariantCulture);
                        break;
                    case TokenKind.Identifier when token.Text is "true" or "false":
                        meta[key] = token.Text;
                        break;
                    case TokenKind.Punct when token.Text == "-" && Peek().Kind == TokenKind.Number:
                        meta[key] = (-Next().Number).ToString(CultureInfo.InvariantCulture);
                        break;
                    default:
                        throw Error("meta 值格式无效");
                }
            }
        }

        private void ParseStrings()
        {
            while (Peek().Kind == TokenKind.Reference && Peek().Text.StartsWith('$'))
            {
                var reference = Next().Text;
                if (reference.EndsWith('*'))
                {
                    throw Error("字符串定义不能使用通配符");
                }

                ExpectPunct("=");
                var valueToken = ReadStringValue();
                var ascii = false;
                var wide = false;
                var nocase = false;
                var fullword = false;

                while (Peek().Kind == TokenKind.Identifier)
                {
                    var modifier = Peek().Text;
                    if (modifier is "ascii" or "wide" or "nocase" or "fullword")
                    {
                        Next();
                        switch (modifier)
                        {
                            case "ascii":
                                ascii = true;
                                break;
                            case "wide":
                                wide = true;
                                break;
                            case "nocase":
                                nocase = true;
                                break;
                            case "fullword":
                                fullword = true;
                                break;
                        }

                        continue;
                    }

                    if (modifier is "xor" or "base64" or "private" or "base64wide")
                    {
                        throw Error("不支持的字符串修饰符 " + modifier);
                    }

                    break;
                }

                if (!ascii && !wide)
                {
                    ascii = true;
                }

                var index = _strings.Count;
                switch (valueToken.Kind)
                {
                    case TokenKind.String:
                        _strings.Add(new YaraStringDef
                        {
                            Identifier = reference,
                            Index = index,
                            Kind = YaraStringKind.Text,
                            Text = valueToken.Text,
                            Ascii = ascii,
                            Wide = wide,
                            Nocase = nocase,
                            Fullword = fullword
                        });
                        break;
                    case TokenKind.Punct when valueToken.Text == "hex":
                    {
                        var compiled = CompileHex(valueToken.Raw ?? string.Empty, out var literal);
                        _strings.Add(new YaraStringDef
                        {
                            Identifier = reference,
                            Index = index,
                            Kind = YaraStringKind.Hex,
                            CompiledRegex = compiled,
                            Literal = literal
                        });
                        break;
                    }
                    case TokenKind.Punct when valueToken.Text == "regex":
                    {
                        var compiled = CompileRegex(valueToken.Raw ?? string.Empty, nocase, out var literal);
                        _strings.Add(new YaraStringDef
                        {
                            Identifier = reference,
                            Index = index,
                            Kind = YaraStringKind.Regex,
                            Nocase = nocase,
                            CompiledRegex = compiled,
                            Literal = literal
                        });
                        break;
                    }
                    default:
                        throw Error("字符串值格式无效");
                }
            }
        }

        private Token ReadStringValue()
        {
            SkipTrivia();
            if (_position >= _text.Length)
            {
                throw Error("字符串定义不完整");
            }

            var character = _text[_position];
            if (character == '"')
            {
                var token = ReadToken();
                return token;
            }

            if (character == '/')
            {
                return new Token(TokenKind.Punct, "regex", 0, _position)
                {
                    Raw = ReadRawRegex()
                };
            }

            if (character == '{')
            {
                return new Token(TokenKind.Punct, "hex", 0, _position)
                {
                    Raw = ReadRawHex()
                };
            }

            throw Error("字符串值必须以引号、正则或十六进制块开始");
        }

        private string ReadRawRegex()
        {
            _position++;
            var builder = new StringBuilder();
            while (_position < _text.Length)
            {
                var character = _text[_position];
                if (character == '\\' && _position + 1 < _text.Length)
                {
                    var next = _text[_position + 1];
                    if (next == '/')
                    {
                        builder.Append('/');
                    }
                    else
                    {
                        builder.Append(character);
                        builder.Append(next);
                    }

                    _position += 2;
                    continue;
                }

                if (character == '/')
                {
                    _position++;
                    return builder.ToString();
                }

                builder.Append(character);
                _position++;
            }

            throw Error("正则字符串未闭合");
        }

        private string ReadRawHex()
        {
            _position++;
            var start = _position;
            var depth = 0;
            while (_position < _text.Length)
            {
                var character = _text[_position];
                if (character == '(')
                {
                    depth++;
                }
                else if (character == ')')
                {
                    depth--;
                }
                else if (character == '}' && depth == 0)
                {
                    var raw = _text[start.._position];
                    _position++;
                    return raw;
                }

                _position++;
            }

            throw Error("十六进制字符串未闭合");
        }

        private Regex CompileHex(string raw, out byte[]? literal)
        {
            var builder = new StringBuilder();
            var bestRun = new List<byte>();
            var currentRun = new List<byte>();
            var depth = 0;
            var index = 0;
            while (index < raw.Length)
            {
                var character = raw[index];
                if (char.IsWhiteSpace(character))
                {
                    index++;
                    continue;
                }

                if (character is '(' or ')' or '|')
                {
                    if (character == '(')
                    {
                        depth++;
                    }
                    else if (character == ')')
                    {
                        depth--;
                    }

                    currentRun.Clear();
                    builder.Append(character switch
                    {
                        '(' => "(?:",
                        ')' => ")",
                        _ => "|"
                    });
                    index++;
                    continue;
                }

                if (character == '[')
                {
                    var end = raw.IndexOf(']', index + 1);
                    if (end < 0)
                    {
                        throw Error("十六进制跳转未闭合");
                    }

                    var content = raw[(index + 1)..end].Trim();
                    if (!TryAppendJump(builder, content))
                    {
                        throw Error("不支持的十六进制跳转");
                    }

                    currentRun.Clear();
                    index = end + 1;
                    continue;
                }

                if (index + 1 < raw.Length && IsHexOrWildcard(character) && IsHexOrWildcard(raw[index + 1]))
                {
                    AppendNibblePair(builder, character, raw[index + 1]);
                    if (depth == 0 && character != '?' && raw[index + 1] != '?')
                    {
                        currentRun.Add(Convert.ToByte(raw.Substring(index, 2), 16));
                        if (currentRun.Count > bestRun.Count)
                        {
                            bestRun = new List<byte>(currentRun);
                        }
                    }
                    else
                    {
                        currentRun.Clear();
                    }

                    index += 2;
                    continue;
                }

                throw Error("无效的十六进制字节 '" + character + "'");
            }

            literal = bestRun.Count >= 4 ? bestRun.ToArray() : null;
            return new Regex(builder.ToString(), RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        }

        private static bool TryAppendJump(StringBuilder builder, string content)
        {
            if (content.Length == 0)
            {
                return false;
            }

            var dash = content.IndexOf('-');
            if (dash < 0)
            {
                if (!int.TryParse(content, NumberStyles.None, CultureInfo.InvariantCulture, out var exact) || exact < 0)
                {
                    return false;
                }

                builder.Append("[\\x00-\\xFF]{").Append(exact).Append('}');
                return true;
            }

            var minimumText = content[..dash].Trim();
            var maximumText = content[(dash + 1)..].Trim();
            if (maximumText.Length == 0)
            {
                return false;
            }

            if (!int.TryParse(minimumText.Length == 0 ? "0" : minimumText, NumberStyles.None, CultureInfo.InvariantCulture, out var minimum) ||
                !int.TryParse(maximumText, NumberStyles.None, CultureInfo.InvariantCulture, out var maximum) ||
                minimum < 0 || maximum < minimum)
            {
                return false;
            }

            builder.Append("[\\x00-\\xFF]{").Append(minimum).Append(',').Append(maximum).Append('}');
            return true;
        }

        private static bool IsHexOrWildcard(char value)
        {
            return value == '?' || Uri.IsHexDigit(value);
        }

        private static void AppendNibblePair(StringBuilder builder, char high, char low)
        {
            if (high == '?' && low == '?')
            {
                builder.Append("[\\x00-\\xFF]");
                return;
            }

            if (high == '?')
            {
                var lowValue = Convert.ToInt32(low.ToString(), 16);
                builder.Append("[");
                for (var nibble = 0; nibble < 16; nibble++)
                {
                    builder.Append("\\x").Append((nibble << 4 | lowValue).ToString("X2", CultureInfo.InvariantCulture));
                }

                builder.Append(']');
                return;
            }

            if (low == '?')
            {
                var highValue = Convert.ToInt32(high.ToString(), 16);
                var lowerBound = (highValue << 4).ToString("X2", CultureInfo.InvariantCulture);
                var upperBound = (highValue << 4 | 0xF).ToString("X2", CultureInfo.InvariantCulture);
                builder.Append("[\\x").Append(lowerBound).Append("-\\x").Append(upperBound).Append(']');
                return;
            }

            builder.Append("\\x").Append(high).Append(low);
        }

        private Regex CompileRegex(string pattern, bool nocase, out byte[]? literal)
        {
            literal = ExtractRegexLiteral(pattern);
            try
            {
                var options = RegexOptions.Compiled | RegexOptions.CultureInvariant;
                if (nocase)
                {
                    options |= RegexOptions.IgnoreCase;
                }

                return new Regex(pattern, options, TimeSpan.FromSeconds(1));
            }
            catch (ArgumentException exception)
            {
                throw Error("正则表达式无效：" + exception.Message);
            }
        }

        private static byte[]? ExtractRegexLiteral(string pattern)
        {
            var builder = new StringBuilder();
            var index = 0;
            while (index < pattern.Length)
            {
                var character = pattern[index];
                if (character == '\\' && index + 1 < pattern.Length)
                {
                    var next = pattern[index + 1];
                    if (next == 'x' && index + 3 < pattern.Length &&
                        Uri.IsHexDigit(pattern[index + 2]) && Uri.IsHexDigit(pattern[index + 3]))
                    {
                        builder.Append((char)Convert.ToByte(pattern.Substring(index + 2, 2), 16));
                        index += 4;
                        continue;
                    }

                    if (char.IsLetterOrDigit(next))
                    {
                        break;
                    }

                    builder.Append(next);
                    index += 2;
                    continue;
                }

                if (char.IsLetterOrDigit(character) || character is ' ' or '_' or '-' or '/' or '@' or ':' or '.')
                {
                    builder.Append(character);
                    index++;
                    continue;
                }

                break;
            }

            if (builder.Length < 4)
            {
                return null;
            }

            return Encoding.UTF8.GetBytes(builder.ToString());
        }

        private YaraExpression ParseExpression() => ParseOr();

        private YaraExpression ParseOr()
        {
            var left = ParseAnd();
            while (Peek().Kind == TokenKind.Identifier && Peek().Text == "or")
            {
                Next();
                left = new YaraBinaryExpression(YaraBinaryOperator.Or, left, ParseAnd());
            }

            return left;
        }

        private YaraExpression ParseAnd()
        {
            var left = ParseNot();
            while (Peek().Kind == TokenKind.Identifier && Peek().Text == "and")
            {
                Next();
                left = new YaraBinaryExpression(YaraBinaryOperator.And, left, ParseNot());
            }

            return left;
        }

        private YaraExpression ParseNot()
        {
            if (Peek().Kind == TokenKind.Identifier && Peek().Text == "not")
            {
                Next();
                return new YaraBinaryExpression(YaraBinaryOperator.Equal, new YaraTruthExpression(false), ParseNot());
            }

            if (Peek().Kind == TokenKind.Identifier && Peek().Text == "defined")
            {
                throw Error("不支持 defined 运算符");
            }

            return ParseComparison();
        }

        private YaraExpression ParseComparison()
        {
            var left = ParseBitwiseOr();
            var token = Peek();
            YaraBinaryOperator? operation = null;

            if (token.Kind == TokenKind.Punct)
            {
                operation = token.Text switch
                {
                    "==" => YaraBinaryOperator.Equal,
                    "!=" => YaraBinaryOperator.NotEqual,
                    "<" => YaraBinaryOperator.LessThan,
                    "<=" => YaraBinaryOperator.LessThanOrEqual,
                    ">" => YaraBinaryOperator.GreaterThan,
                    ">=" => YaraBinaryOperator.GreaterThanOrEqual,
                    _ => null
                };
            }
            else if (token.Kind == TokenKind.Identifier)
            {
                operation = token.Text switch
                {
                    "contains" => YaraBinaryOperator.Contains,
                    "icontains" => YaraBinaryOperator.IContains,
                    "startswith" => YaraBinaryOperator.StartsWith,
                    "endswith" => YaraBinaryOperator.EndsWith,
                    "matches" => YaraBinaryOperator.Matches,
                    _ => null
                };
            }

            if (operation is null)
            {
                return left;
            }

            Next();
            return new YaraBinaryExpression(operation.Value, left, ParseComparison());
        }

        private YaraExpression ParseBitwiseOr()
        {
            var left = ParseBitwiseXor();
            while (Peek().Kind == TokenKind.Punct && Peek().Text == "|")
            {
                Next();
                left = new YaraBinaryExpression(YaraBinaryOperator.BitwiseOr, left, ParseBitwiseXor());
            }

            return left;
        }

        private YaraExpression ParseBitwiseXor()
        {
            var left = ParseBitwiseAnd();
            while (Peek().Kind == TokenKind.Punct && Peek().Text == "^")
            {
                Next();
                left = new YaraBinaryExpression(YaraBinaryOperator.BitwiseXor, left, ParseBitwiseAnd());
            }

            return left;
        }

        private YaraExpression ParseBitwiseAnd()
        {
            var left = ParseShift();
            while (Peek().Kind == TokenKind.Punct && Peek().Text == "&")
            {
                Next();
                left = new YaraBinaryExpression(YaraBinaryOperator.BitwiseAnd, left, ParseShift());
            }

            return left;
        }

        private YaraExpression ParseShift()
        {
            var left = ParseAdditive();
            while (Peek().Kind == TokenKind.Punct && Peek().Text is "<<" or ">>")
            {
                var operation = Next().Text == "<<" ? YaraBinaryOperator.ShiftLeft : YaraBinaryOperator.ShiftRight;
                left = new YaraBinaryExpression(operation, left, ParseAdditive());
            }

            return left;
        }

        private YaraExpression ParseAdditive()
        {
            var left = ParseMultiplicative();
            while (Peek().Kind == TokenKind.Punct && Peek().Text is "+" or "-")
            {
                var operation = Next().Text == "+" ? YaraBinaryOperator.Add : YaraBinaryOperator.Subtract;
                left = new YaraBinaryExpression(operation, left, ParseMultiplicative());
            }

            return left;
        }

        private YaraExpression ParseMultiplicative()
        {
            var left = ParseUnary();
            while (Peek().Kind == TokenKind.Punct && Peek().Text is "*" or "\\" or "/" or "%")
            {
                var text = Next().Text;
                var operation = text switch
                {
                    "*" => YaraBinaryOperator.Multiply,
                    "%" => YaraBinaryOperator.Modulo,
                    _ => YaraBinaryOperator.Divide
                };
                left = new YaraBinaryExpression(operation, left, ParseUnary());
            }

            return left;
        }

        private YaraExpression ParseUnary()
        {
            var token = Peek();
            if (token.Kind == TokenKind.Punct && token.Text is "-" or "~")
            {
                Next();
                var operation = token.Text == "-" ? YaraUnaryOperator.Negate : YaraUnaryOperator.BitwiseNot;
                return new YaraUnaryExpression(operation, ParseUnary());
            }

            return ParsePrimary();
        }

        private YaraExpression ParsePrimary()
        {
            var token = Peek();
            switch (token.Kind)
            {
                case TokenKind.Number:
                {
                    Next();
                    if (Peek().Kind == TokenKind.Punct && Peek().Text == "%")
                    {
                        throw Error("不支持百分比 of 表达式");
                    }

                    if (Peek().Kind == TokenKind.Identifier && Peek().Text == "of")
                    {
                        Next();
                        return ParseStringSet(YaraSetQuantifier.Count, (int)Math.Min(token.Number, int.MaxValue));
                    }

                    return new YaraNumberExpression(token.Number);
                }
                case TokenKind.String:
                    Next();
                    return new YaraTextExpression(token.Text);
                case TokenKind.Reference:
                    return ParseReference();
                case TokenKind.Identifier:
                    return ParseIdentifier();
                case TokenKind.Punct when token.Text == "(":
                {
                    Next();
                    var inner = ParseExpression();
                    ExpectPunct(")");
                    return inner;
                }
                case TokenKind.Punct when token.Text == "/":
                {
                    Next();
                    var pattern = ReadRegexBodyFromCondition();
                    try
                    {
                        return new YaraRegexExpression(new Regex(pattern, ConditionRegexOptions, TimeSpan.FromSeconds(1)));
                    }
                    catch (ArgumentException)
                    {
                        throw Error("条件中的正则表达式无效");
                    }
                }
                default:
                    throw Error("无法解析的 condition 表达式");
            }
        }

        private string ReadRegexBodyFromCondition()
        {
            var builder = new StringBuilder();
            while (_position < _text.Length)
            {
                var character = _text[_position];
                if (character == '\\' && _position + 1 < _text.Length)
                {
                    builder.Append(character).Append(_text[_position + 1]);
                    _position += 2;
                    continue;
                }

                if (character == '/')
                {
                    _position++;
                    _peeked = null;
                    return builder.ToString();
                }

                builder.Append(character);
                _position++;
            }

            throw Error("条件正则未闭合");
        }

        private YaraExpression ParseReference()
        {
            var token = Next();
            var text = token.Text;
            if (text.Length == 0)
            {
                throw Error("无效的字符串引用");
            }

            var sigil = text[0];
            var referenceName = text.Length > 1 ? text[1..] : string.Empty;
            if (referenceName.EndsWith('*'))
            {
                throw Error("通配符字符串引用只能出现在 of 集合中");
            }

            var target = ResolveString("$" + referenceName);
            switch (sigil)
            {
                case '$':
                    return new YaraStringMatchExpression(target.Index);
                case '#':
                    return new YaraStringCountExpression(target.Index);
                case '@':
                {
                    var occurrence = 1;
                    if (Peek().Kind == TokenKind.Punct && Peek().Text == "[")
                    {
                        Next();
                        var number = Next();
                        if (number.Kind != TokenKind.Number || number.Number != 1)
                        {
                            throw Error("只支持 @ 字符串的首个偏移");
                        }

                        ExpectPunct("]");
                    }

                    if (Peek().Kind == TokenKind.Identifier && Peek().Text is "in" or "at")
                    {
                        throw Error("不支持字符串的 in/at 位置谓词");
                    }

                    _ = occurrence;
                    return new YaraStringOffsetExpression(target.Index);
                }
                case '!':
                {
                    if (Peek().Kind == TokenKind.Punct && Peek().Text == "[")
                    {
                        Next();
                        var number = Next();
                        if (number.Kind != TokenKind.Number || number.Number != 1)
                        {
                            throw Error("只支持 ! 字符串的首个长度");
                        }

                        ExpectPunct("]");
                    }

                    return new YaraStringLengthExpression(target.Index);
                }
                default:
                    throw Error("无效的字符串引用");
            }
        }

        private YaraStringDef ResolveString(string identifier)
        {
            var exact = _strings.FirstOrDefault(s => s.Identifier == identifier);
            if (exact is not null)
            {
                return exact;
            }

            if (identifier == "$")
            {
                var anonymous = _strings.FirstOrDefault(s => s.Identifier == "$");
                if (anonymous is not null)
                {
                    return anonymous;
                }
            }

            throw Error("引用未定义的字符串 " + identifier);
        }

        private YaraExpression ParseIdentifier()
        {
            var token = Next();
            var name = token.Text;
            switch (name)
            {
                case "true":
                    return new YaraTruthExpression(true);
                case "false":
                    return new YaraTruthExpression(false);
                case "filesize":
                    return new YaraFileSizeExpression();
                case "any":
                    ExpectIdentifier("of");
                    return ParseStringSet(YaraSetQuantifier.Any, 0);
                case "all":
                    ExpectIdentifier("of");
                    return ParseStringSet(YaraSetQuantifier.All, 0);
                case "for":
                    throw Error("不支持 for 循环");
                case "of":
                    throw Error("of 表达式缺少量词");
            }

            var fullName = name;
            while (Peek().Kind == TokenKind.Punct && Peek().Text == ".")
            {
                Next();
                var member = Next();
                if (member.Kind != TokenKind.Identifier)
                {
                    throw Error("模块成员名称无效");
                }

                fullName += "." + member.Text;
                if (Peek().Kind == TokenKind.Punct && Peek().Text == "[")
                {
                    throw Error("不支持模块数组索引");
                }
            }

            if (Peek().Kind == TokenKind.Punct && Peek().Text == "(")
            {
                Next();
                var arguments = new List<YaraExpression>();
                if (!(Peek().Kind == TokenKind.Punct && Peek().Text == ")"))
                {
                    while (true)
                    {
                        arguments.Add(ParseExpression());
                        if (Peek().Kind == TokenKind.Punct && Peek().Text == ",")
                        {
                            Next();
                            continue;
                        }

                        break;
                    }
                }

                ExpectPunct(")");
                if (!SupportedCalls.Contains(fullName))
                {
                    throw Error("不支持的函数 " + fullName);
                }

                return new YaraCallExpression(fullName, arguments);
            }

            if (SupportedConstants.Contains(fullName))
            {
                return new YaraCallExpression(fullName, Array.Empty<YaraExpression>());
            }

            throw Error("不支持的标识符 " + fullName);
        }

        private YaraExpression ParseStringSet(YaraSetQuantifier quantifier, int threshold)
        {
            var indices = new List<int>();
            if (Peek().Kind == TokenKind.Identifier && Peek().Text == "them")
            {
                Next();
                foreach (var item in _strings)
                {
                    indices.Add(item.Index);
                }
            }
            else if (Peek().Kind == TokenKind.Punct && Peek().Text == "(")
            {
                Next();
                while (true)
                {
                    var token = Next();
                    if (token.Kind != TokenKind.Reference || token.Text[0] != '$')
                    {
                        throw Error("of 集合只能包含字符串引用");
                    }

                    AddReferencedStrings(token.Text, indices);
                    if (Peek().Kind == TokenKind.Punct && Peek().Text == ",")
                    {
                        Next();
                        continue;
                    }

                    break;
                }

                ExpectPunct(")");
            }
            else
            {
                throw Error("of 表达式缺少字符串集合");
            }

            if (indices.Count == 0)
            {
                throw Error("of 集合为空");
            }

            return new YaraStringSetExpression(quantifier, threshold, indices.Distinct().ToArray());
        }

        private void AddReferencedStrings(string reference, List<int> indices)
        {
            var wildcard = reference.EndsWith('*');
            var prefix = wildcard ? reference[..^1] : reference;
            if (wildcard)
            {
                var matches = _strings.Where(s => s.Identifier.StartsWith(prefix, StringComparison.Ordinal)).ToArray();
                if (matches.Length == 0)
                {
                    throw Error("of 集合引用了不存在的字符串 " + reference);
                }

                foreach (var match in matches)
                {
                    indices.Add(match.Index);
                }

                return;
            }

            if (prefix == "$")
            {
                var anonymous = _strings.Where(s => s.Identifier == "$").ToArray();
                if (anonymous.Length == 0)
                {
                    throw Error("of 集合引用了不存在的匿名字符串");
                }

                foreach (var match in anonymous)
                {
                    indices.Add(match.Index);
                }

                return;
            }

            var target = _strings.FirstOrDefault(s => s.Identifier == prefix);
            if (target is null)
            {
                throw Error("of 集合引用了不存在的字符串 " + reference);
            }

            indices.Add(target.Index);
        }

        private void ExpectPunct(string value)
        {
            var token = Next();
            if (token.Kind != TokenKind.Punct || token.Text != value)
            {
                throw Error("期望 '" + value + "'");
            }
        }

        private void ExpectIdentifier(string value)
        {
            var token = Next();
            if (token.Kind != TokenKind.Identifier || token.Text != value)
            {
                throw Error("期望 '" + value + "'");
            }
        }

        private YaraParseException Error(string message) => new($"{_source}:{_line}: {message}");

        private Token Peek()
        {
            _peeked ??= ReadToken();
            return _peeked.Value;
        }

        private Token Next()
        {
            if (_peeked is { } token)
            {
                _peeked = null;
                return token;
            }

            return ReadToken();
        }

        private void SkipTrivia()
        {
            while (_position < _text.Length)
            {
                var character = _text[_position];
                if (char.IsWhiteSpace(character))
                {
                    _position++;
                    continue;
                }

                if (character == '/' && _position + 1 < _text.Length && _text[_position + 1] == '/')
                {
                    _position += 2;
                    while (_position < _text.Length && _text[_position] != '\n')
                    {
                        _position++;
                    }

                    continue;
                }

                if (character == '/' && _position + 1 < _text.Length && _text[_position + 1] == '*')
                {
                    _position += 2;
                    while (_position + 1 < _text.Length && !(_text[_position] == '*' && _text[_position + 1] == '/'))
                    {
                        _position++;
                    }

                    _position = Math.Min(_text.Length, _position + 2);
                    continue;
                }

                break;
            }
        }

        private Token ReadToken()
        {
            SkipTrivia();
            var position = _position;
            if (_position >= _text.Length)
            {
                return new Token(TokenKind.End, string.Empty, 0, position);
            }

            var character = _text[_position];
            if (IsIdentifierStart(character))
            {
                _position++;
                while (_position < _text.Length && IsIdentifierPart(_text[_position]))
                {
                    _position++;
                }

                return new Token(TokenKind.Identifier, _text[position.._position], 0, position);
            }

            if (char.IsAsciiDigit(character))
            {
                return ReadNumber();
            }

            if (character == '"')
            {
                return ReadQuotedString();
            }

            if (character is '$' or '#' or '@' or '!')
            {
                if (character == '!' && _position + 1 < _text.Length && _text[_position + 1] == '=')
                {
                    _position += 2;
                    return new Token(TokenKind.Punct, "!=", 0, position);
                }

                return ReadReference();
            }

            if (_position + 1 < _text.Length)
            {
                var pair = _text.Substring(_position, 2);
                if (pair is "==" or "<=" or ">=" or "<<" or ">>")
                {
                    _position += 2;
                    return new Token(TokenKind.Punct, pair, 0, position);
                }
            }

            _position++;
            return new Token(TokenKind.Punct, character.ToString(), 0, position);
        }

        private Token ReadNumber()
        {
            var position = _position;
            if (_text[_position] == '0' && _position + 1 < _text.Length && (_text[_position + 1] == 'x' || _text[_position + 1] == 'X'))
            {
                _position += 2;
                var start = _position;
                while (_position < _text.Length && Uri.IsHexDigit(_text[_position]))
                {
                    _position++;
                }

                if (_position == start)
                {
                    throw Error("十六进制数字无效");
                }

                var value = long.Parse(_text.AsSpan(start, _position - start), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                return new Token(TokenKind.Number, _text[position.._position], value, position);
            }

            while (_position < _text.Length && char.IsAsciiDigit(_text[_position]))
            {
                _position++;
            }

            var number = long.Parse(_text.AsSpan(position, _position - position), NumberStyles.None, CultureInfo.InvariantCulture);
            if (_position < _text.Length && char.IsAsciiLetter(_text[_position]))
            {
                var suffix = _text[_position];
                var multiplier = suffix switch
                {
                    'K' or 'k' => 1024L,
                    'M' or 'm' => 1024L * 1024,
                    'G' or 'g' => 1024L * 1024 * 1024,
                    _ => 0L
                };

                if (multiplier == 0)
                {
                    throw Error("数字后缀无效");
                }

                _position++;
                if (_position < _text.Length && (_text[_position] == 'B' || _text[_position] == 'b'))
                {
                    _position++;
                }

                number = checked(number * multiplier);
            }

            return new Token(TokenKind.Number, _text[position.._position], number, position);
        }

        private Token ReadQuotedString()
        {
            var position = _position;
            _position++;
            var builder = new StringBuilder();
            while (_position < _text.Length)
            {
                var character = _text[_position];
                if (character == '\\' && _position + 1 < _text.Length)
                {
                    var next = _text[_position + 1];
                    _position += 2;
                    builder.Append(next switch
                    {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '\\' => '\\',
                        '"' => '"',
                        'x' => ReadHexEscape(builder),
                        _ => next
                    });
                    continue;
                }

                if (character == '"')
                {
                    _position++;
                    return new Token(TokenKind.String, builder.ToString(), 0, position);
                }

                builder.Append(character);
                _position++;
            }

            throw Error("字符串未闭合");
        }

        private char ReadHexEscape(StringBuilder builder)
        {
            if (_position + 2 > _text.Length)
            {
                throw Error("非法十六进制转义");
            }

            var hex = _text.Substring(_position, 2);
            if (!byte.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
            {
                throw Error("非法十六进制转义");
            }

            _position += 2;
            return (char)value;
        }

        private Token ReadReference()
        {
            var position = _position;
            var sigil = _text[_position];
            _position++;
            var nameStart = _position;
            while (_position < _text.Length && IsIdentifierPart(_text[_position]))
            {
                _position++;
            }

            if (_position == nameStart && sigil != '$')
            {
                throw Error("字符串引用缺少名称");
            }

            if (_position < _text.Length && _text[_position] == '*')
            {
                _position++;
            }

            return new Token(TokenKind.Reference, _text[position.._position], 0, position);
        }
    }
}
