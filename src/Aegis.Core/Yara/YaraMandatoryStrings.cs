using Aegis.Core.Yara;

namespace Aegis.Core.Yara;

/// <summary>
/// 计算"条件成立时必然命中"的字符串索引集合（must-set）。
/// 只有落入这个集合的字符串才能被当作预过滤条件——用非必要条件做过滤会丢检测。
///
///   all of them        → 全部字符串都是必须的
///   $a and $b          → {a, b}
///   $a or $b           → 交集，通常为空
///   N of them / any of them → 空（不满足任何单个字符串的必要性）
///   not $a             → 空
/// </summary>
public static class YaraMandatoryStrings
{
    /// <summary>返回规则内字符串索引（对应 YaraStringMatchExpression.Index）。</summary>
    public static HashSet<int> Collect(YaraExpression condition)
    {
        var result = new HashSet<int>();
        Walk(condition, result);
        return result;
    }

    private static void Walk(YaraExpression expr, HashSet<int> acc)
    {
        switch (expr)
        {
            case YaraStringMatchExpression match:
                acc.Add(match.Index);
                break;

            case YaraStringSetExpression set when set.Quantifier == YaraSetQuantifier.All:
                foreach (var index in set.Indices)
                {
                    acc.Add(index);
                }

                break;

            // Count / Any：没有任何单个字符串是必要条件
            case YaraStringSetExpression:
                break;

            case YaraBinaryExpression binary when binary.Operator == YaraBinaryOperator.And:
                Walk(binary.Left, acc);
                Walk(binary.Right, acc);
                break;

            case YaraBinaryExpression binary:
            {
                // or/xor/比较等：只有当两侧都必然命中时才成立
                var left = new HashSet<int>();
                Walk(binary.Left, left);
                var right = new HashSet<int>();
                Walk(binary.Right, right);
                left.IntersectWith(right);
                foreach (var index in left)
                {
                    acc.Add(index);
                }

                break;
            }

            case YaraUnaryExpression unary when unary.Operator == YaraUnaryOperator.Negate:
                // not $a 成立意味着 $a 不命中，不能作为必要条件
                break;

            case YaraUnaryExpression unary:
                Walk(unary.Operand, acc);
                break;

            default:
                break;
        }
    }
}
