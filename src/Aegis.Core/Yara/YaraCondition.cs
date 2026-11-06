using System.Text.RegularExpressions;

namespace Aegis.Core.Yara;

public abstract record YaraExpression;

public sealed record YaraNumberExpression(long Value) : YaraExpression;

public sealed record YaraTruthExpression(bool Value) : YaraExpression;

public sealed record YaraTextExpression(string Value) : YaraExpression;

public sealed record YaraRegexExpression(Regex Value) : YaraExpression;

public sealed record YaraStringMatchExpression(int Index) : YaraExpression;

public sealed record YaraStringCountExpression(int Index) : YaraExpression;

public sealed record YaraStringOffsetExpression(int Index) : YaraExpression;

public sealed record YaraStringLengthExpression(int Index) : YaraExpression;

public sealed record YaraFileSizeExpression : YaraExpression;

public sealed record YaraStringSetExpression(YaraSetQuantifier Quantifier, int Threshold, IReadOnlyList<int> Indices) : YaraExpression;

public sealed record YaraUnaryExpression(YaraUnaryOperator Operator, YaraExpression Operand) : YaraExpression;

public sealed record YaraBinaryExpression(YaraBinaryOperator Operator, YaraExpression Left, YaraExpression Right) : YaraExpression;

public sealed record YaraCallExpression(string Name, IReadOnlyList<YaraExpression> Arguments) : YaraExpression;

public enum YaraSetQuantifier
{
    Any,
    All,
    Count
}

public enum YaraUnaryOperator
{
    Negate,
    BitwiseNot
}

public enum YaraBinaryOperator
{
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    ShiftLeft,
    ShiftRight,
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    And,
    Or,
    Contains,
    IContains,
    StartsWith,
    EndsWith,
    Matches
}

public interface IYaraEvaluationContext
{
    long FileSize { get; }

    byte[] Data { get; }

    bool IsMatch(int stringIndex);

    long GetMatchCount(int stringIndex);

    long? GetMatchOffset(int stringIndex);

    long? GetMatchLength(int stringIndex);

    long ReadInteger(int width, long offset, bool bigEndian);

    object? Call(string name, IReadOnlyList<object?> arguments);
}

public static class YaraEvaluator
{
    public static bool IsTruthy(object? value) => value switch
    {
        null => false,
        bool boolean => boolean,
        long number => number != 0,
        string text => text.Length > 0,
        _ => true
    };

    public static bool Evaluate(YaraExpression expression, IYaraEvaluationContext context)
        => IsTruthy(EvaluateValue(expression, context));

    public static object? EvaluateValue(YaraExpression expression, IYaraEvaluationContext context)
    {
        switch (expression)
        {
            case YaraNumberExpression number:
                return number.Value;
            case YaraTruthExpression truth:
                return truth.Value ? 1L : 0L;
            case YaraTextExpression text:
                return text.Value;
            case YaraRegexExpression regex:
                return regex.Value;
            case YaraStringMatchExpression match:
                return context.IsMatch(match.Index) ? 1L : 0L;
            case YaraStringCountExpression count:
                return context.GetMatchCount(count.Index);
            case YaraStringOffsetExpression offset:
                return context.GetMatchOffset(offset.Index);
            case YaraStringLengthExpression length:
                return context.GetMatchLength(length.Index);
            case YaraFileSizeExpression:
                return context.FileSize;
            case YaraStringSetExpression set:
                return EvaluateSet(set, context) ? 1L : 0L;
            case YaraUnaryExpression unary:
                return EvaluateUnary(unary, context);
            case YaraBinaryExpression binary:
                return EvaluateBinary(binary, context);
            case YaraCallExpression call:
                return context.Call(call.Name, call.Arguments.Select(argument => EvaluateValue(argument, context)).ToArray());
            default:
                return null;
        }
    }

    private static bool EvaluateSet(YaraStringSetExpression set, IYaraEvaluationContext context)
    {
        switch (set.Quantifier)
        {
            case YaraSetQuantifier.Any:
                foreach (var index in set.Indices)
                {
                    if (context.IsMatch(index))
                    {
                        return true;
                    }
                }

                return false;
            case YaraSetQuantifier.All:
                if (set.Indices.Count == 0)
                {
                    return false;
                }

                foreach (var index in set.Indices)
                {
                    if (!context.IsMatch(index))
                    {
                        return false;
                    }
                }

                return true;
            case YaraSetQuantifier.Count:
                if (set.Threshold <= 0)
                {
                    return true;
                }

                var matched = 0;
                foreach (var index in set.Indices)
                {
                    if (context.IsMatch(index) && ++matched >= set.Threshold)
                    {
                        return true;
                    }
                }

                return false;
            default:
                return false;
        }
    }

    private static object? EvaluateUnary(YaraUnaryExpression unary, IYaraEvaluationContext context)
    {
        var value = ToNumber(EvaluateValue(unary.Operand, context));
        if (value is null)
        {
            return null;
        }

        return unary.Operator switch
        {
            YaraUnaryOperator.Negate => unchecked(-value.Value),
            YaraUnaryOperator.BitwiseNot => ~value.Value,
            _ => null
        };
    }

    private static object? EvaluateBinary(YaraBinaryExpression binary, IYaraEvaluationContext context)
    {
        if (binary.Operator == YaraBinaryOperator.And)
        {
            return IsTruthy(EvaluateValue(binary.Left, context)) && IsTruthy(EvaluateValue(binary.Right, context)) ? 1L : 0L;
        }

        if (binary.Operator == YaraBinaryOperator.Or)
        {
            return IsTruthy(EvaluateValue(binary.Left, context)) || IsTruthy(EvaluateValue(binary.Right, context)) ? 1L : 0L;
        }

        var left = EvaluateValue(binary.Left, context);
        var right = EvaluateValue(binary.Right, context);

        if (binary.Operator is YaraBinaryOperator.Matches)
        {
            var text = left as string;
            if (text is null)
            {
                return 0L;
            }

            var regex = right as Regex;
            if (regex is null && right is string pattern)
            {
                try
                {
                    regex = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
                }
                catch (ArgumentException)
                {
                    return 0L;
                }
            }

            if (regex is null)
            {
                return 0L;
            }

            try
            {
                return regex.IsMatch(text) ? 1L : 0L;
            }
            catch (RegexMatchTimeoutException)
            {
                return 0L;
            }
        }

        if (binary.Operator is YaraBinaryOperator.Contains or YaraBinaryOperator.IContains or
            YaraBinaryOperator.StartsWith or YaraBinaryOperator.EndsWith)
        {
            var leftText = left as string;
            var rightText = right as string;
            if (leftText is null || rightText is null)
            {
                return 0L;
            }

            var comparison = binary.Operator == YaraBinaryOperator.IContains
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            var result = binary.Operator switch
            {
                YaraBinaryOperator.Contains or YaraBinaryOperator.IContains => leftText.Contains(rightText, comparison),
                YaraBinaryOperator.StartsWith => leftText.StartsWith(rightText, comparison),
                YaraBinaryOperator.EndsWith => leftText.EndsWith(rightText, comparison),
                _ => false
            };
            return result ? 1L : 0L;
        }

        if (binary.Operator is YaraBinaryOperator.Equal or YaraBinaryOperator.NotEqual &&
            left is string leftString && right is string rightString)
        {
            var equal = string.Equals(leftString, rightString, StringComparison.Ordinal);
            return (binary.Operator == YaraBinaryOperator.Equal ? equal : !equal) ? 1L : 0L;
        }

        var leftNumber = ToNumber(left);
        var rightNumber = ToNumber(right);
        if (leftNumber is null || rightNumber is null)
        {
            return null;
        }

        return binary.Operator switch
        {
            YaraBinaryOperator.Add => unchecked(leftNumber.Value + rightNumber.Value),
            YaraBinaryOperator.Subtract => unchecked(leftNumber.Value - rightNumber.Value),
            YaraBinaryOperator.Multiply => unchecked(leftNumber.Value * rightNumber.Value),
            YaraBinaryOperator.Divide => rightNumber.Value == 0 ? null : leftNumber.Value / rightNumber.Value,
            YaraBinaryOperator.Modulo => rightNumber.Value == 0 ? null : leftNumber.Value % rightNumber.Value,
            YaraBinaryOperator.BitwiseAnd => leftNumber.Value & rightNumber.Value,
            YaraBinaryOperator.BitwiseOr => leftNumber.Value | rightNumber.Value,
            YaraBinaryOperator.BitwiseXor => leftNumber.Value ^ rightNumber.Value,
            YaraBinaryOperator.ShiftLeft => leftNumber.Value << (int)(rightNumber.Value & 63),
            YaraBinaryOperator.ShiftRight => leftNumber.Value >> (int)(rightNumber.Value & 63),
            YaraBinaryOperator.Equal => leftNumber.Value == rightNumber.Value ? 1L : 0L,
            YaraBinaryOperator.NotEqual => leftNumber.Value != rightNumber.Value ? 1L : 0L,
            YaraBinaryOperator.LessThan => leftNumber.Value < rightNumber.Value ? 1L : 0L,
            YaraBinaryOperator.LessThanOrEqual => leftNumber.Value <= rightNumber.Value ? 1L : 0L,
            YaraBinaryOperator.GreaterThan => leftNumber.Value > rightNumber.Value ? 1L : 0L,
            YaraBinaryOperator.GreaterThanOrEqual => leftNumber.Value >= rightNumber.Value ? 1L : 0L,
            _ => null
        };
    }

    private static long? ToNumber(object? value) => value switch
    {
        long number => number,
        bool boolean => boolean ? 1 : 0,
        _ => null
    };
}
