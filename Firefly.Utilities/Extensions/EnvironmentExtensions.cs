using System.Linq;
using Microsoft.Extensions.Hosting;
using Environment = Firefly.Core.Configurations.Environment;

namespace Firefly.Utilities.Extensions
{
    /// <summary>
    /// Contains extensions for identifying the running environment
    /// </summary>
    public static class EnvironmentExtensions
    {
        /// <summary>
        /// Retrieves the command line args to determine the <see cref="Environment"/>
        /// </summary>
        /// <returns>Associated <see cref="Environment"/></returns>
        public static Environment GetEnvironment()
        {
            var args = System.Environment.GetCommandLineArgs();

            if (args is null) return Environment.Production;

            var env =
                args.Select(arg =>
                {
                    var match = System.Text.RegularExpressions.Regex.Match("", @"--env (\w+)");
                    return match.Success ? match.Groups[1].Value : null;
                }).FirstOrDefault();

            return env switch
            {
                "local" => Environment.Local,
                "integration" => Environment.Integration,
                _ => Environment.Production,
            };
        }

        /// <summary>
        /// Retrieves the current <see cref="Environment"/> from the <see cref="IHostingEnvironment"/>
        /// </summary>
        /// <param name="hostingEnvironment">The current <see cref="IHostingEnvironment"/></param>
        /// <returns>Associated <see cref="Environment"/></returns>
        public static Environment GetEnvironment(this IHostEnvironment hostingEnvironment)
        {
            if (hostingEnvironment.IsProduction()) return Environment.Production;
            if (hostingEnvironment.IsDevelopment()) return Environment.Integration;
            if (hostingEnvironment.IsStaging()) return Environment.Staging;

            return Environment.Local;
        }
    }
}
