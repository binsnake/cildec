// Fixture source for cildec. Every construct here exists to exercise one part
// of the decoder; see fixtures/README.md for the mapping and the build recipe.
//
// Keep this file small and keep each feature isolated, because the golden dumps
// are compared field by field and a gratuitous edit churns all of them.

using System;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Runtime.InteropServices;

[assembly: Fixtures.FixtureMarker("assembly-level")]

namespace Fixtures;

/// <summary>Marks fixture elements so that CustomAttribute rows exist.</summary>
[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
public sealed class FixtureMarkerAttribute : Attribute
{
    public FixtureMarkerAttribute(string note) => Note = note;

    public string Note { get; }

    public int Rank { get; set; }
}

/// <summary>Generic type with a constraint, exercising GenericParam rows.</summary>
public class Container<T> where T : struct, IComparable<T>
{
    private T[] items = new T[4];

    public int Count { get; private set; }

    public event EventHandler<T>? Added;

    public void Add(T item)
    {
        if (Count == items.Length)
        {
            Array.Resize(ref items, items.Length * 2);
        }

        items[Count++] = item;
        Added?.Invoke(this, item);
    }

    /// <summary>Generic method over a generic type, producing MVar signatures.</summary>
    public TResult Map<TResult>(Func<T, TResult> project, int index) => project(items[index]);

    /// <summary>A nested type inside a generic type.</summary>
    public struct Cursor
    {
        public int Index;

        /// <summary>A type nested two levels deep.</summary>
        public enum State
        {
            Idle,
            Moving,
        }
    }
}

/// <summary>Explicit layout, exercising ClassLayout and FieldLayout.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16, Pack = 4)]
public struct Overlapped
{
    [FieldOffset(0)]
    public int AsInt32;

    [FieldOffset(0)]
    public float AsSingle;

    [FieldOffset(8)]
    public long Tail;
}

/// <summary>Sequential layout with a declared pack, for a second ClassLayout row.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Packed
{
    public byte Tag;

    public long Payload;
}

public static class Interop
{
    /// <summary>A P/Invoke, exercising ImplMap and a body-less MethodDef.</summary>
    [DllImport("kernel32.dll", EntryPoint = "GetTickCount64", SetLastError = true)]
    public static extern ulong GetTickCount64();

    /// <summary>A marshalled P/Invoke, exercising FieldMarshal on a parameter.</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetEnvironmentVariableW(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] char[] buffer,
        int size);
}

public static unsafe class Shapes
{
    /// <summary>A function pointer, exercising ELEMENT_TYPE_FNPTR.</summary>
    public static int Apply(delegate*<int, int> f, int x) => f(x);

    /// <summary>A multi-dimensional array, exercising ELEMENT_TYPE_ARRAY and its shape.</summary>
    public static int Sum(int[,] grid)
    {
        int total = 0;
        for (int i = 0; i < grid.GetLength(0); i++)
        {
            for (int j = 0; j < grid.GetLength(1); j++)
            {
                total += grid[i, j];
            }
        }

        return total;
    }

    /// <summary>A pointer and a byref, exercising PTR and BYREF.</summary>
    public static void Swap(int* left, ref int right)
    {
        (*left, right) = (right, *left);
    }

    /// <summary>A pinned local, exercising ELEMENT_TYPE_PINNED in a LocalVarSig.</summary>
    public static int FirstByte(byte[] data)
    {
        fixed (byte* p = data)
        {
            return p is null ? -1 : *p;
        }
    }

    /// <summary>A field with an RVA, exercising FieldRVA.</summary>
    public static ReadOnlySpan<byte> Magic => new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 };
}

public static class Constants
{
    /// <summary>Every short ldc.i4 encoding the compiler emits.</summary>
    public static int Ladder(int which) => which switch
    {
        0 => -1,
        1 => 0,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 4,
        6 => 5,
        7 => 6,
        8 => 7,
        9 => 8,
        10 => 9,
        11 => 127,
        12 => 1000,
        _ => int.MaxValue,
    };

    /// <summary>Every numeric conversion, exercising the conv.* family.</summary>
    public static void Conversions(double value, out long asI8, out uint asU4, out float asR4)
    {
        asI8 = (long)value;
        asU4 = (uint)value;
        asR4 = (float)value;
    }

    /// <summary>Checked conversions, exercising conv.ovf.*.</summary>
    public static byte CheckedNarrow(int value) => checked((byte)value);

    /// <summary>Unsigned checked conversion, exercising conv.ovf.*.un.</summary>
    public static short CheckedNarrowUnsigned(uint value) => checked((short)value);

    /// <summary>Wide constants, exercising ldc.i8, ldc.r4 and ldc.r8.</summary>
    public static (long, float, double) Wide() => (0x0123_4567_89AB_CDEF, 1.5f, Math.PI);

    /// <summary>String literals, exercising ldstr and the #US heap.</summary>
    public static string Greeting(bool formal) => formal ? "Good evening" : "hi \u00e9\u4e2d";
}

public static class Flow
{
    /// <summary>A dense switch, exercising the switch opcode and its jump table.</summary>
    public static string Dense(int value)
    {
        switch (value)
        {
            case 0: return "zero";
            case 1: return "one";
            case 2: return "two";
            case 3: return "three";
            case 4: return "four";
            case 5: return "five";
            case 6: return "six";
            default: return "many";
        }
    }

    /// <summary>Nested try/finally with leave chains.</summary>
    public static int NestedFinally(int seed)
    {
        int total = seed;
        try
        {
            try
            {
                total += 1;
                if (total > 100)
                {
                    return total;
                }
            }
            finally
            {
                total *= 2;
            }

            total += 3;
        }
        finally
        {
            total -= 1;
        }

        return total;
    }

    /// <summary>A catch with a filter, exercising the Filter clause kind.</summary>
    public static string Filtered(int code)
    {
        try
        {
            if (code < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(code));
            }

            return "ok";
        }
        catch (ArgumentException e) when (e.ParamName == "code")
        {
            return "filtered";
        }
        catch (Exception)
        {
            return "caught";
        }
        finally
        {
            GC.KeepAlive(code);
        }
    }

    /// <summary>A constrained callvirt on a generic value type.</summary>
    public static string Describe<T>(T value) where T : struct => value.ToString() ?? string.Empty;

    /// <summary>A volatile read, exercising the volatile. prefix.</summary>
    public static int VolatileRead(ref int slot) => Volatile.Read(ref slot);
}

/// <summary>An interface plus an explicit implementation, exercising MethodImpl.</summary>
public interface INamed
{
    string Name { get; }

    void Rename(string value);
}

[FixtureMarker("type-level", Rank = 3)]
public sealed class Widget : INamed
{
    private string name = "widget";

    public const int Version = 7;

    string INamed.Name => name;

    void INamed.Rename(string value) => name = value;

    [FixtureMarker("method-level")]
    public int Compute(int a, int b = 4) => a * b + Version;

    public int this[int index] => index * 2;

    public override string ToString() => name;
}
