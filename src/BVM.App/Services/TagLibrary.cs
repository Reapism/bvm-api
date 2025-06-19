using System.IO;
using System.Linq.Expressions;

namespace BVM.App.Services
{
    /// <summary>
    /// Parameters passed into file-based rules.
    /// </summary>
    public record FileRuleParameters(FileInfo FileInfo);

    /// <summary>
    /// Parameters passed into directory-based rules.
    /// </summary>
    public record DirectoryRuleParameters(DirectoryInfo DirectoryInfo);

    /// <summary>
    /// Represents a file-based rule that can be evaluated later.
    /// </summary>
    public class FileRule
    {
        public Expression<Func<FileRuleParameters, bool>> CriteriaExpression { get; }
        public bool IsEnabled { get; set; }

        private readonly Lazy<Func<FileRuleParameters, bool>> _compiled;

        public FileRule(Expression<Func<FileRuleParameters, bool>> criteriaExpression, bool isEnabled)
        {
            CriteriaExpression = criteriaExpression ?? throw new ArgumentNullException(nameof(criteriaExpression));
            IsEnabled = isEnabled;
            _compiled = new Lazy<Func<FileRuleParameters, bool>>(criteriaExpression.Compile);
        }

        /// <summary>
        /// Evaluates this rule against the given parameters.
        /// </summary>
        public bool Evaluate(FileRuleParameters parameters)
            => IsEnabled && _compiled.Value(parameters);
    }

    /// <summary>
    /// Represents a directory-based rule that can be evaluated later.
    /// </summary>
    public class DirectoryRule
    {
        public Expression<Func<DirectoryRuleParameters, bool>> CriteriaExpression { get; }
        public bool IsEnabled { get; set; }

        private readonly Lazy<Func<DirectoryRuleParameters, bool>> _compiled;

        public DirectoryRule(Expression<Func<DirectoryRuleParameters, bool>> criteriaExpression, bool isEnabled)
        {
            CriteriaExpression = criteriaExpression ?? throw new ArgumentNullException(nameof(criteriaExpression));
            IsEnabled = isEnabled;
            _compiled = new Lazy<Func<DirectoryRuleParameters, bool>>(criteriaExpression.Compile);
        }

        /// <summary>
        /// Evaluates this rule against the given parameters.
        /// </summary>
        public bool Evaluate(DirectoryRuleParameters parameters)
            => IsEnabled && _compiled.Value(parameters);
    }

    public record Tag(string Name, string[] Strings);

    public interface ITagCollectionProvider
    {
        ICollection<Tag> Tags { get; }
    }

    public enum LogicalOperator
    {
        Equals,
        NotEquals,
        LessThan,
        LessThanOrEqualTo,
        MoreThan,
        MoreThanOrEqualTo,
    }

    /// <summary>
    /// Central library for registering and evaluating file/directory rules.
    /// </summary>
    public class TagLibrary
    {
        private readonly List<FileRule> _fileRules = new();
        private readonly List<DirectoryRule> _directoryRules = new();

        /// <summary>
        /// Read-only collection of registered file rules.
        /// </summary>
        public IReadOnlyCollection<FileRule> FileRules => _fileRules.AsReadOnly();

        /// <summary>
        /// Read-only collection of registered directory rules.
        /// </summary>
        public IReadOnlyCollection<DirectoryRule> DirectoryRules => _directoryRules.AsReadOnly();

        /// <summary>
        /// Adds a new file-based rule for later evaluation.
        /// </summary>
        public void AddFileRule(Expression<Func<FileRuleParameters, bool>> ruleExpression, bool isEnabled = true)
        {
            _fileRules.Add(new FileRule(ruleExpression, isEnabled));
        }

        /// <summary>
        /// Adds a new directory-based rule for later evaluation.
        /// </summary>
        public void AddDirectoryRule(Expression<Func<DirectoryRuleParameters, bool>> ruleExpression, bool isEnabled = true)
        {
            _directoryRules.Add(new DirectoryRule(ruleExpression, isEnabled));
        }

        /// <summary>
        /// Evaluates all enabled file rules against the given FileInfo.
        /// </summary>
        public IEnumerable<FileRule> EvaluateFileRules(FileInfo file)
        {
            var parameters = new FileRuleParameters(file);
            return _fileRules.Where(r => r.Evaluate(parameters));
        }

        /// <summary>
        /// Evaluates all enabled directory rules against the given DirectoryInfo.
        /// </summary>
        public IEnumerable<DirectoryRule> EvaluateDirectoryRules(DirectoryInfo directory)
        {
            var parameters = new DirectoryRuleParameters(directory);
            return _directoryRules.Where(r => r.Evaluate(parameters));
        }
    }
}
