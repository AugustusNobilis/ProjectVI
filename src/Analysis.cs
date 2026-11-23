using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Xml;
using System.Xml.Linq;

namespace CompatPrep;

internal record Asset(string Path, long Bytes, string Kind, string? Format = null);
internal record Binding(string Consumer, string Library, string Symbol, bool Delay, string Group, string Evidence, string? Forward, string? WindowsApiSetHost);
internal record ManifestRef(string Manifest, string Target, bool Present);
internal record ScanResult(DateTimeOffset Utc, List<Asset> Assets, Dictionary<string,ImageInfo> Images,
    List<ManifestRef> EntryPoints, List<Binding> Bindings, List<string> Limits);

internal static class Analysis
{
    public static readonly JsonSerializerOptions Json = new() { WriteIndented=true, Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static bool Contract(string s) => s.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) ||
        s.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);
    private static string Family(string module)
    {
        var n=module.ToLowerInvariant();
        if(n.Contains("d3d12_x") || n.Contains("d3d12.x") || n.Contains("d3d11_x") || n.Contains("d3d11.x")) return "Xbox graphics";
        if(n.Contains("xbox") || n.Contains("scarlett") || n.Contains("durango")) return "Xbox platform";
        if(n.Contains("xgameruntime") || n.Contains("gameinput") || n.StartsWith("xgame")) return "Gaming services";
        if(n.Contains("d3d") || n.Contains("dxgi")) return "Graphics";
        if(n.Contains("http") || n.Contains("curl") || n.Contains("winsock") || n.StartsWith("ws2_")) return "Network";
        return Contract(n) ? "Windows API set" : "Other";
    }
    public static ScanResult Scan(PackageFiles package)
    {
        var assets=new List<Asset>();
        var images=new Dictionary<string,ImageInfo>(StringComparer.OrdinalIgnoreCase);
        var exports=new Dictionary<string,ExportTable>(StringComparer.OrdinalIgnoreCase);
        var manifests=new List<(string Manifest,string Target)>();
        var limits=new List<string>();
        foreach(string path in package.Enumerate(limits))
        {
            try
            {
                using var f=package.Open(path);
                var magic=new byte[4];
                f.ReadExactly(magic.AsSpan(0,(int)Math.Min(f.Length,4))); f.Position=0;
                var ext=Path.GetExtension(path).ToLowerInvariant();
                if (magic[0]=='M' && magic[1]=='Z')
                {
                    assets.Add(new(path,f.Length,"MZ"));
                    using var pe=new PeFile(f);
                    var image=pe.Inspect(); images.Add(path,image);
                    if(image.Role=="dll") exports[path]=pe.Exports();
                    continue;
                }
                string kind=ext switch { ".rpf"=>"RPF", ".ttpf"=>"TTPF", ".xvd"=>"XVD", ".bin" or ".pri"=>"binary", _=>"other" };
                string? format=null;
                if(kind=="RPF")
                {
                    string tag=Encoding.ASCII.GetString(magic);
                    if(tag.EndsWith("FPR",StringComparison.Ordinal)) tag=new string(tag.Reverse().ToArray());
                    format=tag.StartsWith("RPF",StringComparison.Ordinal) && char.IsAsciiLetterOrDigit(tag[3]) ? tag : "unrecognized";
                }
                assets.Add(new(path,f.Length,kind,format));
                var name=Path.GetFileName(path);
                if(name.Equals("MicrosoftGame.config",StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("AppxManifest.xml",StringComparison.OrdinalIgnoreCase))
                {
                    using var xr=XmlReader.Create(f,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,
                        XmlResolver=null,MaxCharactersInDocument=4*1024*1024});
                    foreach(var node in XDocument.Load(xr).Descendants())
                    foreach(var a in node.Attributes())
                        if((a.Name.LocalName.Equals("Executable",StringComparison.OrdinalIgnoreCase) ||
                            (node.Name.LocalName.Equals("Executable",StringComparison.OrdinalIgnoreCase) && a.Name.LocalName.Equals("Name",StringComparison.OrdinalIgnoreCase))) &&
                            a.Value.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))
                            manifests.Add((path,a.Value));
                }
            }
            catch(Exception e) when(e is IOException or UnauthorizedAccessException or BadImageFormatException or OverflowException or XmlException or ArgumentException)
            { limits.Add(path+" ["+e.GetType().Name+"]"); }
        }
        var paths=assets.Select(x=>x.Path.Replace('/','\\')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var refs=manifests.Distinct().Select(m=>new ManifestRef(m.Manifest,m.Target,paths.Contains(m.Target.Replace('/','\\')))).ToList();
        var available=assets.Where(a=>Path.GetExtension(a.Path).Equals(".dll",StringComparison.OrdinalIgnoreCase))
            .ToLookup(a=>Path.GetFileName(a.Path),a=>a.Path,StringComparer.OrdinalIgnoreCase);
        var desktop=new Dictionary<string,(string Status,ExportTable? Table)>(StringComparer.OrdinalIgnoreCase);
        var bindings=new List<Binding>();
        var schema=ApiSchema.Load(limits);
        foreach(var (path,im) in images)
        foreach(var imp in im.Imports.Distinct())
        {
            string status; string? forward=null;
            string? apiHost=Contract(imp.Module)?schema.Resolve(imp.Module,path):null;
            string[] pkg=available[imp.Module].ToArray();
            if(pkg.Length>1) status="package-ambiguous";
            else if(pkg.Length==1) status=exports.TryGetValue(pkg[0],out var table) ?
                Lookup(table,imp.Symbol,"package",out forward) : "package-unparsed";
            else if(Contract(imp.Module) && apiHost==null) status="api-set-unresolved";
            else
            {
                string target=apiHost ?? imp.Module;
                if(!desktop.TryGetValue(target,out var host)) desktop[target]=host=HostExports(target);
                status=host.Table==null ? host.Status : Lookup(host.Table,imp.Symbol,"desktop",out forward);
            }
            bindings.Add(new(path,imp.Module,imp.Symbol,imp.Delayed,Family(imp.Module),status,forward,apiHost));
        }
        return new(DateTimeOffset.UtcNow,assets,images,refs,bindings,limits);
    }
    private static string Lookup(ExportTable table,string symbol,string prefix,out string? forward)
        => table.Values.TryGetValue(symbol,out forward) ? prefix+(forward==null?"-export":"-forward") : prefix+"-symbol-missing";
    private static (string,ExportTable?) HostExports(string name)
    {
        if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) return ("host-unavailable",null);
        if(!System.Text.RegularExpressions.Regex.IsMatch(name,@"\A[A-Za-z0-9_.-]+\.dll\z",System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            return ("nonstandard-module",null);
        try { var host=new PackageFiles(Environment.SystemDirectory);using var f=host.Open(name);using var pe=new PeFile(f);return ("desktop",pe.Exports()); }
        catch(FileNotFoundException){return ("not-in-package-or-system32",null);}
        catch(Exception e) when(e is IOException or BadImageFormatException or OverflowException or UnauthorizedAccessException or ArgumentException)
        {return ("host-unparsed",null);}
    }
    public static string Summary(ScanResult r)
    {
        var b=new StringBuilder();
        b.AppendLine("# Compatibility research summary").AppendLine();
        b.AppendLine($"Snapshot UTC {r.Utc:yyyy-MM-dd HH:mm:ss}. Inventoried files: {r.Assets.Count}. DLL: {r.Images.Values.Count(v=>v.Role=="dll")}. Skipped entries and read errors: {r.Limits.Count}.");
        b.AppendLine($"Manifest entry points: {r.EntryPoints.Select(x=>x.Target).Distinct(StringComparer.OrdinalIgnoreCase).Count()}. Present at the declared paths: {r.EntryPoints.Where(x=>x.Present).Select(x=>x.Target).Distinct(StringComparer.OrdinalIgnoreCase).Count()}.");
        b.AppendLine().AppendLine("## Containers").AppendLine().AppendLine("| Type | Files | GiB |").AppendLine("|---|---:|---:|");
        foreach(var g in r.Assets.Where(x=>x.Kind is "RPF" or "TTPF" or "XVD").GroupBy(x=>x.Kind).OrderBy(g=>g.Key))
            b.AppendLine($"| {g.Key} | {g.Count()} | {g.Sum(x=>x.Bytes)/1073741824.0:F2} |");
        b.AppendLine().AppendLine("The JSON includes the RPF format signature and the extensions and sizes of TTPF and XVD files. Container contents were not extracted.");
        b.AppendLine().AppendLine("## Imports").AppendLine().AppendLine("Each count represents a consumer, library, symbol and import method. The complete function and forwarder list is in compatibility.json.")
            .AppendLine().AppendLine("| Lookup result | Bindings |").AppendLine("|---|---:|");
        foreach(var g in r.Bindings.GroupBy(x=>x.Evidence).OrderByDescending(g=>g.Count())) b.AppendLine($"| {g.Key} | {g.Count()} |");
        b.AppendLine().AppendLine("## Graphics dependencies").AppendLine();
        foreach(var g in r.Bindings.Where(x=>x.Group.Contains("graphics",StringComparison.OrdinalIgnoreCase)).GroupBy(x=>x.Library,StringComparer.OrdinalIgnoreCase))
        {
            b.AppendLine($"- {g.Key} — {g.Select(x=>x.Symbol).Distinct().Count()} unique symbols.");
            foreach(var symbol in g.Select(x=>x.Symbol).Distinct().Order()) b.AppendLine("  - "+symbol);
        }
        b.AppendLine().AppendLine("## Manual review").AppendLine()
            .AppendLine("Modules or symbols with no export found by the package and System32 lookup. Identical imports from different consumers are grouped.").AppendLine();
        foreach(var g in r.Bindings.Where(x=>x.Evidence is "not-in-package-or-system32" or "desktop-symbol-missing" or "package-symbol-missing")
            .GroupBy(x=>x.Library,StringComparer.OrdinalIgnoreCase).OrderBy(g=>g.Key))
            b.AppendLine($"- {g.Key} — "+string.Join(", ",g.Select(x=>x.Symbol).Distinct().Order())+".");
        var unresolved=r.Bindings.Where(x=>x.Evidence=="api-set-unresolved").ToList();
        b.AppendLine().AppendLine($"API-set contracts without an exact match in the system schema: {unresolved.Select(x=>x.Library).Distinct(StringComparer.OrdinalIgnoreCase).Count()}. Import bindings: {unresolved.Count}. Filter these records by the Evidence field in the JSON.");
        b.AppendLine().AppendLine("package-export and desktop-export indicate a name or ordinal in an export table. API sets use exact-name matching against the local v6 schema; WindowsApiSetHost records the resolved system DLL. An export does not establish ABI or behavioral compatibility. forward identifies a forwarder. Forwarding chains and dynamic lookups need further investigation. Host-library lookup is restricted to System32.");
        return b.ToString();
    }
}
