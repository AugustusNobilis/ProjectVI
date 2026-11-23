using System.Text;
using System.Text.RegularExpressions;

namespace CompatPrep;

internal record HostCandidate(string Module,string? Forward,string? RelatedContract);
internal record TriageRow(string Library,string Symbol,string[] Consumers,int References,
    string Result,HostCandidate[] Candidates);
internal record TriageResult(DateTimeOffset SourceScanUtc,string[] SystemModulesChecked,
    string[] SystemModulesUnparsed,TriageRow[] Rows,SdkLookup SdkHeaders);

internal static class ImportTriage
{
    // Named candidates on this particular Windows installation. This is deliberately not a
    // loader search path and does not assert ownership of a symbol with the same spelling.
    private static readonly string[] CommonHosts=(
        "kernel32 kernelbase ntdll ucrtbase msvcrt vcruntime140 msvcp140 advapi32 " +
        "sechost bcrypt bcryptprimitives ncrypt crypt32 ole32 oleaut32 combase rpcrt4 " +
        "user32 gdi32 win32u shcore shell32 shlwapi propsys version cfgmgr32 setupapi " +
        "winhttp wininet ws2_32 iphlpapi dnsapi normaliz secur32 sspicli " +
        "d3d11 d3d12 dxgi dxcore dwrite dcomp winmm mmdevapi avrt xinput1_4 gameinput " +
        "xaudio2_9 dxguid powrprof userenv wtsapi32").Split(' ',StringSplitOptions.RemoveEmptyEntries);

    private static bool Pending(Binding b) => b.Evidence is "api-set-unresolved" or "not-in-package-or-system32"
        or "desktop-symbol-missing" or "package-symbol-missing";
    private static string? Special(string name) => name is "D3D12CreateRootSignatureDeserializer" or
        "D3D12SerializeVersionedRootSignature" ? "desktop-root-signature-export" : null;

    public static TriageResult Run(ScanResult report)
    {
        var failures=new List<string>();
        var schema=ApiSchema.Load(failures);
        var system=new PackageFiles(Environment.SystemDirectory);
        var cache=new Dictionary<string,ExportTable?>(StringComparer.OrdinalIgnoreCase);
        ExportTable? Read(string host)
        {
            if(cache.TryGetValue(host,out var cached))return cached;
            if(!Regex.IsMatch(host,@"\A[A-Za-z0-9_.-]+\.dll\z",RegexOptions.IgnoreCase))
                return null;
            try { using var stream=system.Open(host);using var pe=new PeFile(stream);return cache[host]=pe.Exports(); }
            catch(FileNotFoundException) { return cache[host]=null; }
            catch(Exception e) when(e is IOException or UnauthorizedAccessException or InvalidDataException or BadImageFormatException or ArgumentException or OverflowException)
            { failures.Add(host+" ["+e.GetType().Name+"]");return cache[host]=null; }
        }
        var rows=new List<TriageRow>();
        foreach(var group in report.Bindings.Where(Pending).GroupBy(b=>(b.Library,b.Symbol)).OrderBy(g=>g.Key.Library).ThenBy(g=>g.Key.Symbol))
        {
            var (library,symbol)=group.Key;
            var consumers=group.Select(b=>b.Consumer).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToArray();
            var candidates=new List<HostCandidate>();
            // Ordinals are module-local and cannot be correlated by name across DLLs.
            if(!symbol.StartsWith('#'))
            {
                // Aliases in the API-set schema can be importer-specific. Only promote a
                // nearby contract when the candidate is applicable to ALL consumers.
                var related=schema.Nearby(library,consumers[0]).Where(c=>
                    consumers.All(consumer=>string.Equals(schema.Resolve(c.Contract,consumer),c.Host,StringComparison.OrdinalIgnoreCase)));
                foreach(var (contract,host) in related)
                    if(Read(host) is {} table && table.Values.TryGetValue(symbol,out var forward))
                        candidates.Add(new(host,forward,contract));
                foreach(string name in CommonHosts)
                {
                    string host=name+".dll";
                    if(candidates.Any(c=>c.Module.Equals(host,StringComparison.OrdinalIgnoreCase)))continue;
                    if(Read(host) is {} table && table.Values.TryGetValue(symbol,out var forward))
                        candidates.Add(new(host,forward,null));
                }
            }
            string result;
            if(symbol.StartsWith('#')) result="ordinal-needs-original-module";
            else if(group.Any(b=>b.Group=="Xbox graphics") && Special(symbol) is {} special &&
                    candidates.Any(c=>c.Module.Equals("d3d12.dll",StringComparison.OrdinalIgnoreCase))) result=special;
            else if(candidates.Any(c=>c.RelatedContract!=null)) result="nearby-api-set-export";
            else if(candidates.Count>0) result="other-module-same-export-name";
            else result="no-candidate-in-checked-modules";
            rows.Add(new(library,symbol,consumers,group.Count(),result,candidates.ToArray()));
        }
        var sdk=SdkLookup.Check(rows.Where(r=>r.Result=="no-candidate-in-checked-modules").Select(r=>r.Symbol));
        return new(report.Utc,cache.Where(p=>p.Value!=null).Select(p=>p.Key).Order().ToArray(),
            failures.ToArray(),rows.ToArray(),sdk);
    }
    public static string Summary(TriageResult result)
    {
        var b=new StringBuilder();
        b.AppendLine("# Unresolved imports and Windows candidates").AppendLine()
            .AppendLine($"Source report snapshot — {result.SourceScanUtc:yyyy-MM-dd HH:mm:ss} UTC. " +
                $"System-module export tables checked: {result.SystemModulesChecked.Length}. " +
                $"Unique library/symbol pairs: {result.Rows.Length}. Import bindings: {result.Rows.Sum(r=>r.References)}.")
            .AppendLine().AppendLine("| Evidence | Pairs | Bindings |").AppendLine("|---|---:|---:|");
        var titles=new Dictionary<string,string>{
            ["desktop-root-signature-export"]="Direct3D root-signature functions found in the desktop library",
            ["nearby-api-set-export"]="Exact symbol in a system module for a nearby contract revision",
            ["other-module-same-export-name"]="Matching export name in another Windows module",
            ["no-candidate-in-checked-modules"]="No candidate in the checked modules",
            ["ordinal-needs-original-module"]="Ordinal import tied to its original library"};
        foreach(var g in result.Rows.GroupBy(r=>r.Result).OrderBy(g=>g.Key))
            b.AppendLine($"| {titles[g.Key]} | {g.Count()} | {g.Sum(r=>r.References)} |");
        b.AppendLine().AppendLine("## Initial manual review queue").AppendLine();
        var unknown=result.Rows.Where(r=>r.Result is "no-candidate-in-checked-modules" or "ordinal-needs-original-module").ToArray();
        if(unknown.Length==0)b.AppendLine("Every pair has at least one name-based candidate.");
        foreach(var g in unknown.GroupBy(r=>r.Library).OrderByDescending(g=>g.Sum(r=>r.References)))
            b.AppendLine("- "+g.Key+" — "+string.Join(", ",g.Select(r=>r.Symbol))+".");
        var sdk=result.SdkHeaders;
        if(sdk.Status=="searched")
            b.AppendLine().AppendLine($"Additional exact-name search in Windows SDK headers and IDL {sdk.Version}: files read {sdk.FilesRead}, skipped {sdk.Skipped}. Names with a text match: {sdk.Mentions.Count(p=>p.Value.Count>0)} of {sdk.Mentions.Count}. Matching paths are listed in SdkHeaders.Mentions. A header mention does not establish an export or ABI compatibility.");
        b.AppendLine().AppendLine("import-triage.json lists consumers, candidate system modules, nearby contract revisions and forwarders for each pair. Resolution statuses remain unchanged in the original map.")
            .AppendLine().AppendLine("Matching uses exact symbol spelling and distinguishes direct exports from forwarders. " +
                "A matching name or nearby contract revision does not validate the ABI, behavior or final forwarding target. " +
                "Coverage is limited to SystemModulesChecked. Dynamic calls and imports from an absent or unparsed executable are outside this assessment.");
        return b.ToString();
    }
}
