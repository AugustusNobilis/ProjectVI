using System.Text;
using System.Text.Json;
namespace CompatPrep;

internal static class Program
{
    internal static PackageFiles View(string root) => new(root,Path.Combine(root,"_pc_compat"),Path.Combine(root,"_local_security_audit"));

    private static int Main(string[] args)
    {
        try
        {
            switch(args)
            {
                case ["analyze",var root]:
                {
                    var pkg=View(root);
                    string prep=Path.Combine(pkg.Root,"_pc_compat");
                    string output=Path.Combine(prep,"reports");
                    foreach(var dir in new[]{prep,output})
                        if(Directory.Exists(dir) && (File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0)
                            throw new IOException("The output directory is redirected.");
                    Directory.CreateDirectory(output);
                    var result=Analysis.Scan(pkg);
                    var triage=ImportTriage.Run(result);
                    Save(Path.Combine(output,"compatibility.json"),JsonSerializer.Serialize(result,Analysis.Json));
                    Save(Path.Combine(output,"SUMMARY.md"),Analysis.Summary(result));
                    Save(Path.Combine(output,"import-triage.json"),JsonSerializer.Serialize(triage,Analysis.Json));
                    Save(Path.Combine(output,"IMPORT_TRIAGE.md"),ImportTriage.Summary(triage));
                    Console.WriteLine("LOCAL_COMPATIBILITY_REPORT_READY");return 0;
                }
                case ["range",var root,var relative,var offset,var length]:
                    using(var stream=View(root).Open(relative))
                        Console.WriteLine(PackageFiles.RangeHash(stream,long.Parse(offset),long.Parse(length)));
                    return 0;
                case ["graphics"]:
                    Console.WriteLine(JsonSerializer.Serialize(HostGraphics.Probe(),Analysis.Json));return 0;
                case ["selftest"]:
                    SelfTest.Run();Console.WriteLine("SELFTEST_PASS");return 0;
                default:
                    Console.Error.WriteLine("analyze <package> | range <package> <relative-file> <offset> <length> | graphics | selftest");return 2;
            }
        }
        catch(Exception e) { Console.Error.WriteLine("LOCAL_CHECK_FAILED: "+e.GetType().Name);return 1; }
    }
    private static void Save(string path,string data)
    {
        string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try { File.WriteAllText(temp,data,new UTF8Encoding(false));File.Move(temp,path,true); }
        finally { if(File.Exists(temp)) File.Delete(temp); }
    }
}
