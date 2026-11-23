using System.Security.Cryptography;
using System.Text;
namespace CompatPrep;

internal static class SelfTest
{
    private static void Assert(bool good) { if(!good) throw new InvalidOperationException("Self-test failed"); }

    // This inert byte array has no machine code. It describes a PE with a normal and a
    // delay import, imports by name/ordinal, an exported name, a forwarder, and a hole.
    private static byte[] Sample()
    {
        byte[] b=new byte[0xa00];
        void W(int i,int n)=>BitConverter.GetBytes((ushort)n).CopyTo(b,i);
        void D(int i,int n)=>BitConverter.GetBytes(n).CopyTo(b,i);
        void Q(int i,ulong n)=>BitConverter.GetBytes(n).CopyTo(b,i);
        void S(int i,string s)=>Encoding.ASCII.GetBytes(s).CopyTo(b,i);
        const int pe=0x80, opt=pe+24, sec=opt+240;
        W(0,0x5a4d);D(60,pe);D(pe,0x4550);W(pe+4,0x8664);W(pe+6,1);W(pe+20,240);W(pe+22,0x2002);
        W(opt,0x20b);Q(opt+24,0x140000000);D(opt+32,4096);D(opt+36,512);D(opt+56,0x2000);D(opt+60,0x200);
        W(opt+68,3);D(opt+108,16);
        S(sec,".rdata");D(sec+8,0x800);D(sec+12,0x1000);D(sec+16,0x800);D(sec+20,0x200);
        D(opt+112,0x1300);D(opt+116,0xb0);D(opt+120,0x1000);D(opt+124,40);
        D(opt+112+13*8,0x1100);D(opt+116+13*8,64);
        D(0x200,0x1070);D(0x20c,0x1050);D(0x210,0x1070);S(0x250,"normal.dll");Q(0x270,0x1090);Q(0x278,0x8000000000000007);S(0x292,"First");
        D(0x300,1);D(0x304,0x1150);D(0x310,0x1170);S(0x350,"delayed.dll");Q(0x370,0x1190);S(0x392,"Later");
        D(0x510,5);D(0x514,3);D(0x518,1);D(0x51c,0x1340);D(0x520,0x1350);D(0x524,0x1360);
        D(0x540,0x1500);D(0x544,0x1380);D(0x550,0x1370);W(0x560,1);S(0x570,"Forward");S(0x580,"other.Real");
        return b;
    }
    public static void Run()
    {
        var data=Sample();using var f=new MemoryStream(data);using var pe=new PeFile(f);
        var info=pe.Inspect();Assert(info.Imports.Count==3 && info.Imports.Contains(new("normal.dll","#7",false)) &&
            info.Imports.Contains(new("normal.dll","First",false)) && info.Imports.Contains(new("delayed.dll","Later",true)));
        var exp=pe.Exports().Values;Assert(exp["#5"]==null && exp["Forward"]=="other.Real" && !exp.ContainsKey("#7"));
        Assert(PackageFiles.RangeHash(f,511,29)==Convert.ToHexStringLower(SHA256.HashData(data.AsSpan(511,29))));
        bool badRange=false;try{PackageFiles.RangeHash(f,long.MaxValue,2);}catch(ArgumentOutOfRangeException){badRange=true;}Assert(badRange);
        var view=new PackageFiles(Environment.CurrentDirectory);bool traversal=false;
        try{using var invalid=view.Open("../package.bin");}catch(ArgumentException){traversal=true;}Assert(traversal);
        BitConverter.GetBytes(0x7fffffff).CopyTo(data,0x20c);
        using var malformed=new PeFile(new MemoryStream(data));bool badPe=false;
        try{malformed.Inspect();}catch(BadImageFormatException){badPe=true;}Assert(badPe);

        // The same analysis path must pick up an EXE supplied after the first report.
        string root=Directory.CreateTempSubdirectory("pc-compat-fixture-").FullName;
        string manifest=Path.Combine(root,"MicrosoftGame.config"), exe=Path.Combine(root,"synthetic.exe");
        try
        {
            File.WriteAllText(manifest,"<Game><ExecutableList><Executable Name='synthetic.exe'/></ExecutableList></Game>");
            Assert(!Analysis.Scan(Program.View(root)).EntryPoints.Single().Present);
            byte[] fixture=Sample();
            BitConverter.GetBytes((ushort)2).CopyTo(fixture,0x80+22);
            File.WriteAllBytes(exe,fixture);
            var ready=Analysis.Scan(Program.View(root));
            Assert(ready.EntryPoints.Single().Present && ready.Images["synthetic.exe"].Role=="executable" &&
                ready.Bindings.Any(b=>b.Consumer=="synthetic.exe" && b.Delay && b.Symbol=="Later"));
        }
        finally { File.Delete(exe);File.Delete(manifest);Directory.Delete(root); }
    }
}
