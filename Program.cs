using BenchmarkDotNet.Running;

namespace Pbkdf2PsuedoHandleBench
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkSwitcher.FromTypes(new[] {
                typeof(Pbkdf2Bench),
            }).Run(args);
        }
    }


}
