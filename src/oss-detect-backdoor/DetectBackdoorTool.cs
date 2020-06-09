// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.ApplicationInspector.Commands;
using Microsoft.CST.OpenSource.Shared;

namespace Microsoft.CST.OpenSource
{
    public class DetectBackdoorTool : OSSGadget
    {
        /// <summary>
        /// Name of this tool.
        /// </summary>
        private const string TOOL_NAME = "oss-detect-backdoor";

        /// <summary>
        /// Holds the version string, from the assembly.
        /// </summary>
        private static readonly string VERSION = typeof(DetectBackdoorTool).Assembly?.GetName().Version?.ToString() ?? string.Empty;

        /// <summary>
        /// Location of the backdoor detection rules.
        /// </summary>
        private const string RULE_DIRECTORY = @"Resources\BackdoorRules";

        /// <summary>
        /// Command line options
        /// </summary>
        private readonly Dictionary<string, object?> Options = new Dictionary<string, object?>()
        {
            { "target", new List<string>() },
            { "download-directory", null },
            { "use-cache", false },
            { "format", "text" },
            { "output-file", null }
        };

        /// <summary>
        /// Main entrypoint for the download program.
        /// </summary>
        /// <param name="args">parameters passed in from the user</param>
        static async Task Main(string[] args)
        {
            var detectBackdoorTool = new DetectBackdoorTool();
            Logger?.Debug($"Microsoft OSS Gadget - {TOOL_NAME} {VERSION}");
            detectBackdoorTool.ParseOptions(args);

            // output to console or file?
            bool redirectConsole = !string.IsNullOrEmpty((string?)detectBackdoorTool.Options["output-file"]);
            if (redirectConsole && detectBackdoorTool.Options["output-file"] is string outputLoc)
            {
                if (!ConsoleHelper.RedirectConsole(outputLoc))
                {
                    Logger?.Error("Could not switch output from console to file");
                    // continue with current output
                }
            }

            // select output format
            OutputBuilder outputBuilder;
            try
            {
                outputBuilder = new OutputBuilder(((string?)detectBackdoorTool.Options["format"] ??
                    OutputBuilder.OutputFormat.text.ToString()));
            }
            catch (ArgumentOutOfRangeException)
            {
                Logger?.Error("Invalid output format");
                return;
            }

            if (detectBackdoorTool.Options["target"] is IList<string> targetList && targetList.Count > 0)
            {
                var characteristicTool = new CharacteristicTool();
                characteristicTool.Options["target"] = detectBackdoorTool.Options["target"];
                characteristicTool.Options["disable-default-rules"] = true;
                characteristicTool.Options["custom-rule-directory"] = RULE_DIRECTORY;
                characteristicTool.Options["download-directory"] = detectBackdoorTool.Options["download-directory"];
                characteristicTool.Options["use-cache"] = detectBackdoorTool.Options["use-cache"];

                foreach (var target in targetList)
                {
                    try
                    {
                        var purl = new PackageURL(target);
                        var analysisResults = characteristicTool.AnalyzePackage(purl,
                            (string?)detectBackdoorTool.Options["download-directory"], 
                            (bool?)detectBackdoorTool.Options["use-cache"] == true).Result;
                        characteristicTool.AppendOutput(outputBuilder, purl, analysisResults);
                    }
                    catch (Exception ex)
                    {
                        Logger?.Warn(ex, "Error processing {0}: {1}", target, ex.Message);
                    }
                }
                outputBuilder.PrintOutput();
            }
            else
            {
                Logger?.Warn("No target provided; nothing to analyze.");
                DetectBackdoorTool.ShowUsage();
                Environment.Exit(1);
            }
        }

        public DetectBackdoorTool() : base()
        {
        }

        /// <summary>
        /// Parses options for this program.
        /// </summary>
        /// <param name="args">arguments (passed in from the user)</param>
        private void ParseOptions(string[] args)
        {
            if (args == null)
            {
                ShowUsage();
                Environment.Exit(1);
            }

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-h":
                    case "--help":
                        ShowUsage();
                        Environment.Exit(1);
                        break;

                    case "-v":
                    case "--version":
                        Console.Error.WriteLine($"{TOOL_NAME} {VERSION}");
                        Environment.Exit(1);
                        break;

                    case "--download-directory":
                        Options["download-directory"] = args[++i];
                        break;

                    case "--use-cache":
                        Options["use-cache"] = true;
                        break;

                    case "--format":
                        Options["format"] = args[++i];
                        break;

                    case "--output-file":
                        Options["output-file"] = args[++i];
                        break;

                    default:
                        if (Options["target"] is IList<string> targetList)
                        {
                            targetList.Add(args[i]);
                        }
                        break;
                }
            }
        }

        /// <summary>
        /// Displays usage information for the program.
        /// </summary>
        private static void ShowUsage()
        {
            Console.Error.WriteLine($@"
{TOOL_NAME} {VERSION}

Usage: {TOOL_NAME} [options] package-url...

positional arguments:
    package-url                 PackgeURL specifier to download (required, repeats OK)

{BaseProjectManager.GetCommonSupportedHelpText()}

optional arguments:
  --download-directory          the directory to download the package to
  --use-cache                   do not download the package if it is already present in the destination directory
  --format                      selct the output format (text|sarifv1|sarifv2). (default is text)
  --output-file                 send the command output to a file instead of stdout
  --help                        show this help message and exit
  --version                     show version of this tool
");
        }
    }
}
