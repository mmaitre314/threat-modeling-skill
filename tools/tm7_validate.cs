// tm7_validate — Validate TM7 files using TMT's own DataContractSerializer types.
// Auto-discovers the TMT ClickOnce install; override with TMT_DIR env var if needed.
using System.Reflection;
using System.Runtime.Serialization;
using System.Xml;

class Program
{
    static string FindTmtDir()
    {
        // 1. Explicit override
        var env = Environment.GetEnvironmentVariable("TMT_DIR");
        if (!string.IsNullOrEmpty(env) && Directory.Exists(env))
            return env;

        // 2. Auto-discover from ClickOnce cache
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appsRoot = Path.Combine(localAppData, "Apps", "2.0");
        if (Directory.Exists(appsRoot))
        {
            // Find all ThreatModeling.Model.dll files and pick the newest
            try
            {
                var candidates = Directory.GetFiles(appsRoot, "ThreatModeling.Model.dll", SearchOption.AllDirectories)
                    .Where(f => File.Exists(Path.Combine(Path.GetDirectoryName(f), "TMT7.exe")))
                    .ToArray();
                if (candidates.Length > 0)
                {
                    var best = candidates
                        .OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc)
                        .First();
                    return Path.GetDirectoryName(best);
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        return null;
    }

    static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: tm7_validate.exe <file1.tm7> [file2.tm7] ...");
            Console.Error.WriteLine("Auto-discovers TMT install, or set TMT_DIR to override.");
            return 1;
        }

        var tmtDir = FindTmtDir();
        if (tmtDir == null)
        {
            Console.Error.WriteLine("ERROR: Microsoft Threat Modeling Tool not found.");
            Console.Error.WriteLine("  Install TMT from https://aka.ms/threatmodelingtool");
            Console.Error.WriteLine("  or set TMT_DIR to the folder containing ThreatModeling.Model.dll.");
            return 1;
        }
        Console.Error.WriteLine("Using TMT: " + tmtDir);
        AppDomain.CurrentDomain.AssemblyResolve += (sender, e) =>
        {
            var name = new AssemblyName(e.Name).Name;
            var dll = Path.Combine(tmtDir, name + ".dll");
            if (File.Exists(dll)) return Assembly.LoadFrom(dll);
            return null;
        };

        var asm = Assembly.LoadFrom(Path.Combine(tmtDir, "ThreatModeling.Model.dll"));

        // Search all assemblies for SerializableModelData
        var smdType = asm.GetType("ThreatModeling.Model.SerializableModelData");
        if (smdType == null)
        {
            // It might be defined by a method return type
            var omType2 = asm.GetType("ThreatModeling.Model.ObjectModel");
            var createMethod = omType2.GetMethod("CreateSerializableModelData", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (createMethod != null)
            {
                smdType = createMethod.ReturnType;
            }
        }
        if (smdType == null)
        {
            // Brute force: search all types
            foreach (var t in asm.GetTypes())
            {
                if (t.Name.Contains("Serializ"))
                    Console.WriteLine("  Found: " + t.FullName);
            }
            // Also check other DLLs
            foreach (var dllName in new string[] { "ThreatModeling.Common.dll", "ThreatModeling.KnowledgeBase.dll", "ThreatModeling.ViewModel.dll", "ThreatModeling.ExternalStorage.Abstracts.dll" })
            {
                var dllPath = Path.Combine(tmtDir, dllName);
                if (!File.Exists(dllPath)) continue;
                try
                {
                    var a2 = Assembly.LoadFrom(dllPath);
                    foreach (var t in a2.GetTypes())
                    {
                        if (t.Name.Contains("Serializ"))
                            Console.WriteLine("  Found(" + dllName + "): " + t.FullName);
                    }
                }
                catch (Exception) { }
            }
            Console.Error.WriteLine("SerializableModelData not found!");
            return 1;
        }

        // Gather known types from all TMT assemblies (only DataContract/Serializable types)
        var knownTypes = new System.Collections.Generic.List<Type>();
        // Add common framework collection types used in TM7 files
        knownTypes.Add(typeof(string[]));
        foreach (var dllName in new string[] { "ThreatModeling.Model.dll", "ThreatModeling.KnowledgeBase.dll", "ThreatModeling.Common.dll", "ThreatModeling.ExternalStorage.dll", "ThreatModeling.ExternalStorage.Abstracts.dll", "ThreatModeling.ExternalStorage.Local.dll" })
        {
            var dllPath = Path.Combine(tmtDir, dllName);
            if (!File.Exists(dllPath)) continue;
            try
            {
                var a = Assembly.LoadFrom(dllPath);
                foreach (var t in a.GetTypes())
                {
                    if (t.IsGenericTypeDefinition || t.Name.Contains("<") || t.Name.Contains("AnonymousType"))
                        continue;
                    bool hasDC = t.GetCustomAttributes(typeof(DataContractAttribute), false).Length > 0;
                    bool hasCDC = t.GetCustomAttributes(typeof(CollectionDataContractAttribute), false).Length > 0;
                    if (hasDC || hasCDC)
                        knownTypes.Add(t);
                }
            }
            catch (Exception) { }
        }
        Console.Error.WriteLine("Loaded " + knownTypes.Count + " known types from TMT assemblies.");

        // Validate each file
        int failures = 0;
        foreach (var path in args)
        {
            Console.Write(Path.GetFileName(path) + ": ");
            try
            {
                var dcs = new DataContractSerializer(smdType, knownTypes);
                using (var fs = File.OpenRead(path))
                using (var reader = XmlDictionaryReader.CreateTextReader(fs, XmlDictionaryReaderQuotas.Max))
                {
                    var obj = dcs.ReadObject(reader, false);
                    Console.WriteLine("OK");
                }
            }
            catch (Exception ex)
            {
                failures++;
                Console.WriteLine("FAILED");
                Console.Error.WriteLine("  " + ex.GetType().Name + ": ");
                var msg = ex.Message;
                if (msg.Length > 800) msg = msg.Substring(0, 800);
                Console.Error.WriteLine("    " + msg);
                var inner = ex.InnerException;
                int depth = 0;
                while (inner != null && depth < 5)
                {
                    msg = inner.Message;
                    if (msg.Length > 800) msg = msg.Substring(0, 800);
                    Console.Error.WriteLine("  Inner[" + depth + "]: " + inner.GetType().Name + ": " + msg);
                    inner = inner.InnerException;
                    depth++;
                }
            }
        }
        return failures;
    }
}
