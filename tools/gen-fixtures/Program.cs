// Emits fixtures/IlFeatures.dll, an assembly holding the CIL constructs that a
// C# compiler will not produce: vararg methods, `calli`, `fault` handlers,
// `tail.` calls, `no.` prefixes and an explicitly built `switch`.
//
// It uses PersistedAssemblyBuilder rather than ILAsm so that the only tool
// needed to regenerate a fixture is the pinned .NET SDK. Run from the
// repository root:
//
//     dotnet run --project tools/gen-fixtures -- fixtures/IlFeatures.dll

using System.Reflection;
using System.Reflection.Emit;

var output = args.Length > 0 ? args[0] : "fixtures/IlFeatures.dll";

var name = new AssemblyName("IlFeatures") { Version = new Version(1, 0, 0, 0) };
var assembly = new PersistedAssemblyBuilder(name, typeof(object).Assembly);
var module = assembly.DefineDynamicModule("IlFeatures.dll");
var type = module.DefineType("IlFixtures.Features", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);

var varargSum = EmitVarargSum(type);
EmitVarargCaller(type, varargSum);
EmitCalli(type);
EmitFault(type);
EmitFilterAndFault(type);
EmitTailCall(type);
EmitNoPrefix(type);
EmitSparseSwitch(type);
EmitAllLoadConstants(type);
EmitAllConversions(type);
EmitPointerOps(type);

type.CreateType();

var directory = Path.GetDirectoryName(Path.GetFullPath(output));
if (!string.IsNullOrEmpty(directory))
{
    Directory.CreateDirectory(directory);
}

assembly.Save(output);
Console.Error.WriteLine($"wrote {output}");

// ---------------------------------------------------------------------------

static MethodBuilder EmitVarargSum(TypeBuilder type)
{
    // int VarargSum(int first, __arglist) -- exercises a VARARG MethodDefSig
    // and the arglist/refanytype/refanyval family.
    var method = type.DefineMethod(
        "VarargSum",
        MethodAttributes.Public | MethodAttributes.Static,
        CallingConventions.VarArgs,
        typeof(int),
        new[] { typeof(int) });
    var il = method.GetILGenerator();
    var handle = il.DeclareLocal(typeof(ArgIterator));
    il.Emit(OpCodes.Ldloca, handle);
    il.Emit(OpCodes.Arglist);
    il.Emit(OpCodes.Call, typeof(ArgIterator).GetConstructor(new[] { typeof(RuntimeArgumentHandle) })!);
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ret);
    return method;
}

static void EmitVarargCaller(TypeBuilder type, MethodBuilder varargSum)
{
    // A call site with a SENTINEL in its MethodRefSig.
    var method = type.DefineMethod(
        "CallVararg",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        Type.EmptyTypes);
    var il = method.GetILGenerator();
    il.Emit(OpCodes.Ldc_I4_1);
    il.Emit(OpCodes.Ldc_I4_2);
    il.Emit(OpCodes.Ldstr, "three");
    il.EmitCall(OpCodes.Call, varargSum, new[] { typeof(int), typeof(string) });
    il.Emit(OpCodes.Ret);
}

static void EmitCalli(TypeBuilder type)
{
    // An indirect call through a StandAloneSig, exercising `calli`.
    var method = type.DefineMethod(
        "IndirectAdd",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        new[] { typeof(IntPtr), typeof(int), typeof(int) });
    var il = method.GetILGenerator();
    il.Emit(OpCodes.Ldarg_1);
    il.Emit(OpCodes.Ldarg_2);
    il.Emit(OpCodes.Ldarg_0);
    il.EmitCalli(
        OpCodes.Calli,
        System.Runtime.InteropServices.CallingConvention.Cdecl,
        typeof(int),
        new[] { typeof(int), typeof(int) });
    il.Emit(OpCodes.Ret);
}

static void EmitFault(TypeBuilder type)
{
    // A `fault` handler, which C# never emits on its own.
    var method = type.DefineMethod(
        "WithFault",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        new[] { typeof(int) });
    var il = method.GetILGenerator();
    var result = il.DeclareLocal(typeof(int));
    il.BeginExceptionBlock();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ldc_I4_1);
    il.Emit(OpCodes.Add);
    il.Emit(OpCodes.Stloc, result);
    il.BeginFaultBlock();
    il.Emit(OpCodes.Ldc_I4_M1);
    il.Emit(OpCodes.Stloc, result);
    il.EndExceptionBlock();
    il.Emit(OpCodes.Ldloc, result);
    il.Emit(OpCodes.Ret);
}

static void EmitFilterAndFault(TypeBuilder type)
{
    // Nested protected regions: an outer try/finally whose body contains a
    // filtered catch, producing a lexically nested exception table.
    var method = type.DefineMethod(
        "NestedRegions",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        new[] { typeof(int) });
    var il = method.GetILGenerator();
    var result = il.DeclareLocal(typeof(int));

    il.BeginExceptionBlock();
    il.BeginExceptionBlock();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Stloc, result);
    il.Emit(OpCodes.Ldloc, result);
    il.Emit(OpCodes.Ldc_I4_0);
    var skip = il.DefineLabel();
    il.Emit(OpCodes.Bge, skip);
    il.Emit(OpCodes.Newobj, typeof(InvalidOperationException).GetConstructor(Type.EmptyTypes)!);
    il.Emit(OpCodes.Throw);
    il.MarkLabel(skip);
    il.BeginExceptFilterBlock();
    il.Emit(OpCodes.Isinst, typeof(InvalidOperationException));
    il.Emit(OpCodes.Ldnull);
    il.Emit(OpCodes.Cgt_Un);
    il.BeginCatchBlock(null!);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_I4_S, (sbyte)42);
    il.Emit(OpCodes.Stloc, result);
    il.EndExceptionBlock();
    il.BeginFinallyBlock();
    il.Emit(OpCodes.Ldloc, result);
    il.Emit(OpCodes.Ldc_I4_2);
    il.Emit(OpCodes.Mul);
    il.Emit(OpCodes.Stloc, result);
    il.EndExceptionBlock();

    il.Emit(OpCodes.Ldloc, result);
    il.Emit(OpCodes.Ret);
}

static void EmitTailCall(TypeBuilder type)
{
    // `tail. call`, which Roslyn does not emit.
    var method = type.DefineMethod(
        "TailCall",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        new[] { typeof(int) });
    var il = method.GetILGenerator();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Tailcall);
    il.Emit(OpCodes.Call, typeof(Math).GetMethod("Abs", new[] { typeof(int) })!);
    il.Emit(OpCodes.Ret);
}

static void EmitNoPrefix(TypeBuilder type)
{
    // `no. { typecheck | rangecheck | nullcheck } ldelem.i4`, the only prefix
    // that System.Reflection.Emit cannot express, emitted as raw bytes.
    var method = type.DefineMethod(
        "NoChecks",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        new[] { typeof(int[]), typeof(int) });
    var il = method.GetILGenerator();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ldarg_1);
    // System.Reflection.Emit has no `no.` opcode, so the three bytes are
    // spelled with opcodes whose encodings happen to be 0xFE, 0x19 and 0x05.
    il.Emit(OpCodes.Prefix1);   // 0xFE
    il.Emit(OpCodes.Ldc_I4_3);  // 0x19 -> the second byte of `no.`
    il.Emit(OpCodes.Ldarg_3);   // 0x05 -> typecheck | nullcheck
    il.Emit(OpCodes.Ldelem_I4);
    il.Emit(OpCodes.Ret);
}

static void EmitSparseSwitch(TypeBuilder type)
{
    // A switch with an explicit jump table.
    var method = type.DefineMethod(
        "Switch",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(int),
        new[] { typeof(int) });
    var il = method.GetILGenerator();
    var labels = new Label[8];
    for (var i = 0; i < labels.Length; i++)
    {
        labels[i] = il.DefineLabel();
    }

    var fallthrough = il.DefineLabel();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Switch, labels);
    il.Emit(OpCodes.Br, fallthrough);
    for (var i = 0; i < labels.Length; i++)
    {
        il.MarkLabel(labels[i]);
        il.Emit(OpCodes.Ldc_I4, i * 100);
        il.Emit(OpCodes.Ret);
    }

    il.MarkLabel(fallthrough);
    il.Emit(OpCodes.Ldc_I4_M1);
    il.Emit(OpCodes.Ret);
}

static void EmitAllLoadConstants(TypeBuilder type)
{
    // Every ldc encoding, so that the operand decoder is covered end to end.
    var method = type.DefineMethod(
        "LoadConstants",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(void),
        Type.EmptyTypes);
    var il = method.GetILGenerator();
    foreach (var op in new[]
             {
                 OpCodes.Ldc_I4_M1, OpCodes.Ldc_I4_0, OpCodes.Ldc_I4_1, OpCodes.Ldc_I4_2,
                 OpCodes.Ldc_I4_3, OpCodes.Ldc_I4_4, OpCodes.Ldc_I4_5, OpCodes.Ldc_I4_6,
                 OpCodes.Ldc_I4_7, OpCodes.Ldc_I4_8,
             })
    {
        il.Emit(op);
        il.Emit(OpCodes.Pop);
    }

    il.Emit(OpCodes.Ldc_I4_S, (sbyte)-128);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_I4_S, (sbyte)127);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_I4, int.MinValue);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_I4, int.MaxValue);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_I8, long.MinValue);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_R4, float.NegativeInfinity);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldc_R8, double.Epsilon);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldnull);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldstr, "constant");
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ldtoken, typeof(int));
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ret);
}

static void EmitAllConversions(TypeBuilder type)
{
    // Every conv opcode, checked and unchecked, signed and unsigned.
    var method = type.DefineMethod(
        "Conversions",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(void),
        new[] { typeof(long) });
    var il = method.GetILGenerator();
    foreach (var op in new[]
             {
                 OpCodes.Conv_I1, OpCodes.Conv_I2, OpCodes.Conv_I4, OpCodes.Conv_I8,
                 OpCodes.Conv_U1, OpCodes.Conv_U2, OpCodes.Conv_U4, OpCodes.Conv_U8,
                 OpCodes.Conv_I, OpCodes.Conv_U, OpCodes.Conv_R4, OpCodes.Conv_R8,
                 OpCodes.Conv_R_Un,
                 OpCodes.Conv_Ovf_I1, OpCodes.Conv_Ovf_I2, OpCodes.Conv_Ovf_I4,
                 OpCodes.Conv_Ovf_I8, OpCodes.Conv_Ovf_U1, OpCodes.Conv_Ovf_U2,
                 OpCodes.Conv_Ovf_U4, OpCodes.Conv_Ovf_U8, OpCodes.Conv_Ovf_I,
                 OpCodes.Conv_Ovf_U,
                 OpCodes.Conv_Ovf_I1_Un, OpCodes.Conv_Ovf_I2_Un, OpCodes.Conv_Ovf_I4_Un,
                 OpCodes.Conv_Ovf_I8_Un, OpCodes.Conv_Ovf_U1_Un, OpCodes.Conv_Ovf_U2_Un,
                 OpCodes.Conv_Ovf_U4_Un, OpCodes.Conv_Ovf_U8_Un, OpCodes.Conv_Ovf_I_Un,
                 OpCodes.Conv_Ovf_U_Un,
             })
    {
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(op);
        il.Emit(OpCodes.Pop);
    }

    il.Emit(OpCodes.Ret);
}

static void EmitPointerOps(TypeBuilder type)
{
    // `unaligned.` and `volatile.` on an indirect store, plus initblk/cpblk.
    var method = type.DefineMethod(
        "PointerOps",
        MethodAttributes.Public | MethodAttributes.Static,
        typeof(void),
        new[] { typeof(IntPtr), typeof(IntPtr), typeof(int) });
    var il = method.GetILGenerator();
    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ldc_I4_7);
    il.Emit(OpCodes.Unaligned, (byte)1);
    il.Emit(OpCodes.Volatile);
    il.Emit(OpCodes.Stind_I4);

    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ldc_I4_0);
    il.Emit(OpCodes.Ldarg_2);
    il.Emit(OpCodes.Initblk);

    il.Emit(OpCodes.Ldarg_0);
    il.Emit(OpCodes.Ldarg_1);
    il.Emit(OpCodes.Ldarg_2);
    il.Emit(OpCodes.Cpblk);

    il.Emit(OpCodes.Ldarg_2);
    il.Emit(OpCodes.Localloc);
    il.Emit(OpCodes.Pop);
    il.Emit(OpCodes.Ret);
}
