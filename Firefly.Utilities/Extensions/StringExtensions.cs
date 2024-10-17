namespace Firefly.Utilities.Extensions
{
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
        public static bool IsNullOrWhitespace(this string? value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Checks is a string is null or empty
        /// </summary>
        /// <param name="value">The string to check</param>
        /// <returns>True if the value is null or empty</returns>
        public static bool IsNullOrEmpty(this string? value)
        {
            return string.IsNullOrEmpty(value);
        }
    }
}
