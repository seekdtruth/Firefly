namespace Firefly.Utilities.Extensions
{
    using System.Diagnostics.CodeAnalysis;

    /// <summary>
    /// Extensions for <see cref="string"/> objects
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Checks is a string is null, empty, or whitespace
        /// </summary>
        /// <param name="value">The string to check</param>
        /// <returns>True if the value is null, empty, or whitespace</returns>
        public static bool IsNullOrWhitespace([NotNullWhen(false)] this string? value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Checks is a string is null or empty
        /// </summary>
        /// <param name="value">The string to check</param>
        /// <returns>True if the value is null or empty</returns>
        public static bool IsNullOrEmpty([NotNullWhen(false)] this string? value)
        {
            return string.IsNullOrEmpty(value);
        }
    }
}
