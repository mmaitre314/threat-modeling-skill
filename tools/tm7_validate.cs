// tm7_validate — Validate TM7 files using TMT's own DataContractSerializer types.
// Auto-discovers the TMT ClickOnce install; override with TMT_DIR env var if needed.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
                // Phase 1: DataContractSerializer deserialization
                var dcs = new DataContractSerializer(smdType, knownTypes);
                using (var fs = File.OpenRead(path))
                using (var reader = XmlDictionaryReader.CreateTextReader(fs, XmlDictionaryReaderQuotas.Max))
                {
                    var obj = dcs.ReadObject(reader, false);
                }

                // Phase 2: XML-level model validation (mirrors TMT's own checks)
                var warnings = ValidateModel(path);
                if (warnings.Count == 0)
                {
                    Console.WriteLine("OK");
                }
                else
                {
                    failures++;
                    Console.WriteLine("WARN (" + warnings.Count + " issues)");
                    foreach (var w in warnings)
                        Console.Error.WriteLine("  " + w);
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

    /// <summary>
    /// XML-level validation that mirrors TMT's model-integrity checks.
    /// Returns a list of human-readable warning strings.
    /// </summary>
    static List<string> ValidateModel(string path)
    {
        var warnings = new List<string>();
        var doc = new XmlDocument();
        doc.Load(path);
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("tm", "http://schemas.datacontract.org/2004/07/ThreatModeling.Model");
        nsMgr.AddNamespace("abs", "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts");
        nsMgr.AddNamespace("a", "http://schemas.microsoft.com/2003/10/Serialization/Arrays");
        nsMgr.AddNamespace("kb", "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase");

        // Collect known TypeIds from KnowledgeBase (<kb:Id> elements)
        var knownTypeIds = new HashSet<string>();
        var kbIdNodes = doc.GetElementsByTagName("Id", "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase");
        for (int i = 0; i < kbIdNodes.Count; i++)
        {
            var text = kbIdNodes[i].InnerText.Trim();
            if (text.Length > 0)
                knownTypeIds.Add(text);
        }

        // Generic type IDs are always valid as TypeIds
        foreach (var g in new[] { "GE.EI", "GE.P", "GE.DS", "GE.DF", "GE.TB", "GE.TB.L", "GE.TB.B" })
            knownTypeIds.Add(g);

        // Find all line elements (Connectors/LineBoundaries) by searching for SourceX anywhere
        // This avoids namespace-path issues since the element names are in the abs namespace
        var srcXNodes = doc.GetElementsByTagName("SourceX", "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts");
        for (int i = 0; i < srcXNodes.Count; i++)
        {
            var lineNode = srcXNodes[i].ParentNode; // the <a:Value> wrapping Connector/LineBoundary
            if (lineNode == null) continue;

            var nameNode = lineNode.SelectSingleNode("abs:Properties//kb:Value", nsMgr);
            var elName = nameNode != null ? nameNode.InnerText.Trim() : "(unnamed)";

            var typeAttr = (lineNode is XmlElement lineEl) ? lineEl.GetAttributeNode("type", "http://www.w3.org/2001/XMLSchema-instance") : null;
            var lineType = typeAttr != null ? typeAttr.Value : "";

            // Check coordinates are not all zero (TMT: "Line element coordinates are corrupted")
            int srcX = ParseInt(lineNode, "SourceX", nsMgr);
            int srcY = ParseInt(lineNode, "SourceY", nsMgr);
            int tgtX = ParseInt(lineNode, "TargetX", nsMgr);
            int tgtY = ParseInt(lineNode, "TargetY", nsMgr);

            if (srcX == 0 && srcY == 0 && tgtX == 0 && tgtY == 0)
                warnings.Add("Line element coordinates are corrupted for '" + elName + "'");

            // Check TypeId is resolvable in KnowledgeBase
            var typeId = GetText(lineNode, "TypeId", nsMgr);
            if (!string.IsNullOrEmpty(typeId) && knownTypeIds.Count > 0 && !knownTypeIds.Contains(typeId))
            {
                var genericId = GetText(lineNode, "GenericTypeId", nsMgr);
                warnings.Add("Unable to resolve type '" + typeId + "' for '" + elName + "', reverted to base generic type '" + genericId + "'");
            }

            // Check SourceGuid/TargetGuid reference valid stencils (for Connectors)
            if (lineType.Contains("Connector"))
            {
                var sourceGuid = GetText(lineNode, "SourceGuid", nsMgr);
                var targetGuid = GetText(lineNode, "TargetGuid", nsMgr);
                var nil = "00000000-0000-0000-0000-000000000000";
                if (sourceGuid == nil || targetGuid == nil)
                    warnings.Add("Connector '" + elName + "' has unresolved endpoint (nil GUID)");
            }
        }

        // Check Borders (stencils) — TypeId resolution
        var typeIdNodes = doc.GetElementsByTagName("TypeId", "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts");
        for (int i = 0; i < typeIdNodes.Count; i++)
        {
            var parent = typeIdNodes[i].ParentNode;
            if (parent == null) continue;
            // Skip lines (already checked above) — only check stencils
            var typeAttr2 = (parent is XmlElement pEl) ? pEl.GetAttributeNode("type", "http://www.w3.org/2001/XMLSchema-instance") : null;
            if (typeAttr2 != null && (typeAttr2.Value.Contains("Connector") || typeAttr2.Value.Contains("LineBoundary")))
                continue;
            // Skip KnowledgeBase elements
            if (typeAttr2 == null) continue;

            var typeId = typeIdNodes[i].InnerText.Trim();
            if (!string.IsNullOrEmpty(typeId) && knownTypeIds.Count > 0 && !knownTypeIds.Contains(typeId))
            {
                var nameNode = parent.SelectSingleNode("abs:Properties//kb:Value", nsMgr);
                var elName = nameNode != null ? nameNode.InnerText.Trim() : "(unnamed)";
                var genericId = GetText(parent, "GenericTypeId", nsMgr);
                warnings.Add("Unable to resolve type '" + typeId + "' for '" + elName + "', reverted to base generic type '" + genericId + "'");
            }
        }

        // Phase 3: DrawingSurfaceModel consistency checks
        var dsmNodes = doc.SelectNodes("//tm:DrawingSurfaceModel", nsMgr);
        if (dsmNodes != null)
        {
            var allDsmGuids = new HashSet<string>();
            foreach (XmlNode dsm in dsmNodes)
            {
                var dsmGuid = GetText(dsm, "Guid", nsMgr);
                if (!string.IsNullOrEmpty(dsmGuid))
                    allDsmGuids.Add(dsmGuid);

                // Check required child elements exist
                var genericTypeId = GetText(dsm, "GenericTypeId", nsMgr);
                if (string.IsNullOrEmpty(genericTypeId))
                    warnings.Add("DrawingSurfaceModel missing GenericTypeId");
                else if (genericTypeId != "DRAWINGSURFACE")
                    warnings.Add("DrawingSurfaceModel GenericTypeId is '" + genericTypeId + "', expected 'DRAWINGSURFACE'");

                var typeId = GetText(dsm, "TypeId", nsMgr);
                if (string.IsNullOrEmpty(typeId))
                    warnings.Add("DrawingSurfaceModel missing TypeId");

                // Check Header exists
                var header = dsm.SelectSingleNode("tm:Header", nsMgr);
                if (header == null)
                    warnings.Add("DrawingSurfaceModel missing Header element");

                // Check Borders exists
                var borders = dsm.SelectSingleNode("tm:Borders", nsMgr);
                if (borders == null)
                    warnings.Add("DrawingSurfaceModel missing Borders element");

                // Check Lines exists
                var lines = dsm.SelectSingleNode("tm:Lines", nsMgr);
                if (lines == null)
                    warnings.Add("DrawingSurfaceModel missing Lines element");

                // Check Zoom exists
                var zoom = dsm.SelectSingleNode("tm:Zoom", nsMgr);
                if (zoom == null)
                    warnings.Add("DrawingSurfaceModel missing Zoom element");

                // Collect element GUIDs from this DSM's Borders
                var elementGuids = new HashSet<string>();
                if (borders != null)
                {
                    foreach (XmlNode kv in borders.ChildNodes)
                    {
                        var val2 = kv.SelectSingleNode("a:Value", nsMgr);
                        if (val2 == null) continue;
                        var guid2 = GetText(val2, "Guid", nsMgr);
                        if (!string.IsNullOrEmpty(guid2))
                            elementGuids.Add(guid2);
                    }
                }

                // Check that Connectors reference elements in same DSM
                if (lines != null)
                {
                    foreach (XmlNode kv in lines.ChildNodes)
                    {
                        var val2 = kv.SelectSingleNode("a:Value", nsMgr);
                        if (val2 == null) continue;
                        var typeAttr3 = (val2 is XmlElement v2El) ? v2El.GetAttributeNode("type", "http://www.w3.org/2001/XMLSchema-instance") : null;
                        var lineType2 = typeAttr3 != null ? typeAttr3.Value : "";
                        if (!lineType2.Contains("Connector")) continue;

                        var nameNode2 = val2.SelectSingleNode("abs:Properties//kb:Value", nsMgr);
                        var elName2 = nameNode2 != null ? nameNode2.InnerText.Trim() : "(unnamed)";
                        var srcGuid = GetText(val2, "SourceGuid", nsMgr);
                        var tgtGuid = GetText(val2, "TargetGuid", nsMgr);
                        var nilG = "00000000-0000-0000-0000-000000000000";

                        if (!string.IsNullOrEmpty(srcGuid) && srcGuid != nilG && !elementGuids.Contains(srcGuid))
                            warnings.Add("Connector '" + elName2 + "' SourceGuid " + srcGuid + " not in same diagram's Borders");
                        if (!string.IsNullOrEmpty(tgtGuid) && tgtGuid != nilG && !elementGuids.Contains(tgtGuid))
                            warnings.Add("Connector '" + elName2 + "' TargetGuid " + tgtGuid + " not in same diagram's Borders");
                    }
                }
            }

            // Check threat DrawingSurfaceGuids reference valid DSMs
            var threatDsGuids = doc.SelectNodes("//kb:DrawingSurfaceGuid", nsMgr);
            if (threatDsGuids != null)
            {
                foreach (XmlNode tds in threatDsGuids)
                {
                    var dsGuid = tds.InnerText.Trim();
                    if (!string.IsNullOrEmpty(dsGuid) && !allDsmGuids.Contains(dsGuid))
                        warnings.Add("Threat references DrawingSurfaceGuid " + dsGuid + " not matching any DSM");
                }
            }
        }

        return warnings;
    }

    static string GetText(XmlNode parent, string localName, XmlNamespaceManager nsMgr)
    {
        var node = parent.SelectSingleNode("abs:" + localName, nsMgr);
        return node != null ? node.InnerText.Trim() : "";
    }

    static int ParseInt(XmlNode parent, string localName, XmlNamespaceManager nsMgr)
    {
        var text = GetText(parent, localName, nsMgr);
        int val;
        return int.TryParse(text, out val) ? val : 0;
    }
}
