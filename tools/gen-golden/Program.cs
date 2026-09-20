// Produces the golden dump of a fixture assembly, for comparison against the
// dump that `tests/golden.rs` produces with cildec.
//
// Metadata, signatures and exception tables come from System.Reflection.Metadata,
// an implementation this crate shares no code with. Instruction names and
// operand shapes come from System.Reflection.Emit.OpCodes, the runtime's own
// opcode table. The IL walk itself is written here, so the disassembly half of
// the comparison checks cildec against the runtime's opcode data rather than
// against a third-party disassembler; see fixtures/README.md.
//
//     dotnet run --project tools/gen-golden -- <image.dll> > fixtures/golden/<name>.txt

using System.Collections.Immutable;
using System.Globalization;
using System.Reflection.Emit;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

// Two modes. With one path, the dump goes to stdout, which is how the committed
// golden files are produced. With `--out <dir>` and any number of paths, each
// assembly is dumped to `<dir>/<stem>.txt` in one process, which is how the
// differential test compares hundreds of real assemblies without paying
// process startup for each one.
if (args.Length < 1)
{
    Console.Error.WriteLine("usage: gen-golden <image.dll>");
    Console.Error.WriteLine("       gen-golden --out <dir> <image.dll>... | @list.txt");
    return 1;
}

if (args[0] == "--out")
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("--out needs a directory");
        return 1;
    }

    var outDir = args[1];
    Directory.CreateDirectory(outDir);
    var written = 0;
    var skipped = 0;

    // A whole framework is a thousand paths, which overruns the Windows
    // command-line limit, so an argument of the form `@file` is a list of
    // paths, one per line.
    var paths = args.Skip(2)
        .SelectMany(a => a.StartsWith('@') ? File.ReadAllLines(a[1..]) : new[] { a })
        .Where(a => a.Length > 0);

    // Dumps are named by position in the list, not by file name: the same
    // assembly name appears in every installed framework version, and naming by
    // stem would silently compare one version against another.
    var index = 0;
    foreach (var path in paths)
    {
        var stem = index.ToString("D5");
        index++;
        try
        {
            var text = Dump(path);
            File.WriteAllText(Path.Combine(outDir, stem + ".txt"), text);
            written++;
        }
        catch (Exception e)
        {
            // An unmanaged DLL, or one this reader will not open. The Rust side
            // treats a missing dump as "skip", so record why and move on.
            File.WriteAllText(
                Path.Combine(outDir, stem + ".skip"),
                path + ": " + e.GetType().Name + ": " + e.Message + "\n");
            skipped++;
        }
    }

    Console.Error.WriteLine($"dumped {written}, skipped {skipped}");
    return 0;
}

Console.Out.Write(Dump(args[0]));
return 0;

static string Dump(string path)
{
    var bytes = File.ReadAllBytes(path);
    using var peReader = new PEReader(ImmutableArray.Create(bytes));
    var reader = peReader.GetMetadataReader();
    var output = new StringBuilder();
    new Dumper(peReader, reader, output).Run();
    return output.ToString().ReplaceLineEndings("\n");
}

internal sealed class Dumper(PEReader pe, MetadataReader reader, StringBuilder output)
{
    private static readonly OpCode[] OneByte = new OpCode[256];
    private static readonly OpCode[] TwoByte = new OpCode[256];
    private static readonly bool[] OneByteSet = new bool[256];
    private static readonly bool[] TwoByteSet = new bool[256];

    static Dumper()
    {
        foreach (var field in typeof(OpCodes).GetFields())
        {
            if (field.FieldType != typeof(OpCode))
            {
                continue;
            }

            var op = (OpCode)field.GetValue(null)!;
            if (op.OpCodeType == OpCodeType.Nternal)
            {
                continue;
            }

            var value = (ushort)op.Value;
            if (op.Size == 1)
            {
                OneByte[value & 0xFF] = op;
                OneByteSet[value & 0xFF] = true;
            }
            else
            {
                TwoByte[value & 0xFF] = op;
                TwoByteSet[value & 0xFF] = true;
            }
        }
    }

    public void Run()
    {
        var headers = pe.PEHeaders;
        var corHeader = headers.CorHeader!;
        Line($"image pe32plus={Bool(headers.PEHeader!.Magic == PEMagic.PE32Plus)} machine=0x{(ushort)headers.CoffHeader.Machine:x4}");
        Line($"cli runtime={corHeader.MajorRuntimeVersion}.{corHeader.MinorRuntimeVersion} " +
             $"ilonly={Bool(corHeader.Flags.HasFlag(CorFlags.ILOnly))} " +
             $"bit32required={Bool(corHeader.Flags.HasFlag(CorFlags.Requires32Bit))} " +
             $"bit32preferred={Bool(corHeader.Flags.HasFlag(CorFlags.Prefers32Bit))}");
        Line($"metadata version={reader.MetadataVersion}");

        foreach (var table in Enum.GetValues<TableIndex>().OrderBy(t => (int)t))
        {
            var count = reader.GetTableRowCount(table);
            if (count > 0)
            {
                Line($"tablerows {table}={count}");
            }
        }

        foreach (var handle in reader.TypeDefinitions)
        {
            DumpType(handle);
        }

        DumpRows();
    }

    private void DumpType(TypeDefinitionHandle handle)
    {
        var type = reader.GetTypeDefinition(handle);
        var rid = MetadataTokens.GetRowNumber(handle);
        var extends = type.BaseType.IsNil ? "-" : TypeName(type.BaseType);
        Line($"type {rid} {FullName(handle)} flags=0x{(int)type.Attributes:x8} extends={extends}");

        var layout = type.GetLayout();
        if (!layout.IsDefault)
        {
            Line($"  layout size={layout.Size} pack={layout.PackingSize}");
        }

        foreach (var fieldHandle in type.GetFields())
        {
            DumpField(fieldHandle);
        }

        foreach (var methodHandle in type.GetMethods())
        {
            DumpMethod(methodHandle);
        }

        DumpMembers(type);
    }

    private void DumpField(FieldDefinitionHandle handle)
    {
        var field = reader.GetFieldDefinition(handle);
        var rid = MetadataTokens.GetRowNumber(handle);
        var signature = field.DecodeSignature(new TypeNames(this), null!);
        var line = new StringBuilder(
            $"  field {rid} {reader.GetString(field.Name)} sig={signature} flags=0x{(int)field.Attributes:x4}");
        var offset = field.GetOffset();
        if (offset >= 0)
        {
            line.Append(CultureInfo.InvariantCulture, $" offset={offset}");
        }

        var marshal = field.GetMarshallingDescriptor();
        if (!marshal.IsNil)
        {
            line.Append(CultureInfo.InvariantCulture, $" marshal={BlobLength(marshal)}");
        }

        var rva = field.GetRelativeVirtualAddress();
        if (rva != 0)
        {
            line.Append(CultureInfo.InvariantCulture, $" rva=0x{rva:x8}");
        }

        Line(line.ToString());
    }

    private void DumpMethod(MethodDefinitionHandle handle)
    {
        var method = reader.GetMethodDefinition(handle);
        var rid = MetadataTokens.GetRowNumber(handle);
        var signature = MethodSignature(method.DecodeSignature(new TypeNames(this), null!));
        Line($"  method {rid} {reader.GetString(method.Name)} sig={signature} " +
             $"flags=0x{(int)method.Attributes:x4} implflags=0x{(int)method.ImplAttributes:x4} " +
             $"rva=0x{method.RelativeVirtualAddress:x8}");

        var import = method.GetImport();
        if (!import.Module.IsNil)
        {
            var module = reader.GetModuleReference(import.Module);
            Line($"    pinvoke module={reader.GetString(module.Name)} " +
                 $"name={reader.GetString(import.Name)} flags=0x{(int)import.Attributes:x4}");
        }

        if (method.RelativeVirtualAddress == 0 ||
            (method.ImplAttributes & MethodImplAttributes.CodeTypeMask) != MethodImplAttributes.IL)
        {
            return;
        }

        var body = pe.GetMethodBody(method.RelativeVirtualAddress);
        var il = body.GetILBytes()!;
        Line($"    maxstack {body.MaxStack} initlocals={Bool(body.LocalVariablesInitialized)} " +
             $"codesize={il.Length}");

        if (!body.LocalSignature.IsNil)
        {
            var locals = reader.GetStandaloneSignature(body.LocalSignature)
                .DecodeLocalSignature(new TypeNames(this), null!);
            for (var i = 0; i < locals.Length; i++)
            {
                Line($"    local {i} {locals[i]}");
            }
        }

        Disassemble(il);

        foreach (var region in body.ExceptionRegions)
        {
            var line = new StringBuilder(
                $"    eh {region.Kind} try=IL_{region.TryOffset:x4}..IL_{region.TryOffset + region.TryLength:x4} " +
                $"handler=IL_{region.HandlerOffset:x4}..IL_{region.HandlerOffset + region.HandlerLength:x4}");
            if (region.Kind == ExceptionRegionKind.Catch)
            {
                line.Append(CultureInfo.InvariantCulture, $" type={TypeName(region.CatchType)}");
            }
            else if (region.Kind == ExceptionRegionKind.Filter)
            {
                line.Append(CultureInfo.InvariantCulture, $" filter=IL_{region.FilterOffset:x4}");
            }

            Line(line.ToString());
        }
    }

    private void Disassemble(byte[] code)
    {
        var offset = 0;
        while (offset < code.Length)
        {
            var start = offset;
            OpCode op;
            if (code[offset] == 0xFE && offset + 2 < code.Length && code[offset + 1] == 0x19)
            {
                // ECMA-335 III.2.2 defines `no.`, but System.Reflection.Emit
                // has no OpCode for it, so it is spelled out here. This is the
                // one instruction whose encoding both sides take from the
                // specification rather than from the runtime table.
                Line($"    il IL_{start:x4} no. {(sbyte)code[offset + 2]}");
                offset += 3;
                continue;
            }

            if (code[offset] == 0xFE)
            {
                if (offset + 1 >= code.Length || !TwoByteSet[code[offset + 1]])
                {
                    Line($"    il IL_{start:x4} <undecodable>");
                    return;
                }

                op = TwoByte[code[offset + 1]];
                offset += 2;
            }
            else
            {
                if (!OneByteSet[code[offset]])
                {
                    Line($"    il IL_{start:x4} <undecodable>");
                    return;
                }

                op = OneByte[code[offset]];
                offset += 1;
            }

            var operand = ReadOperand(op, code, ref offset);
            Line(operand is null
                ? $"    il IL_{start:x4} {op.Name}"
                : $"    il IL_{start:x4} {op.Name} {operand}");
        }
    }

    private string? ReadOperand(OpCode op, byte[] code, ref int offset)
    {
        switch (op.OperandType)
        {
            case OperandType.InlineNone:
                return null;
            case OperandType.ShortInlineI:
            {
                var value = (sbyte)code[offset];
                offset += 1;
                return op == OpCodes.Ldc_I4_S
                    ? ((int)value).ToString(CultureInfo.InvariantCulture)
                    : value.ToString(CultureInfo.InvariantCulture);
            }
            case OperandType.ShortInlineVar:
            {
                var value = code[offset];
                offset += 1;
                return value.ToString(CultureInfo.InvariantCulture);
            }
            case OperandType.InlineVar:
            {
                var value = BitConverter.ToUInt16(code, offset);
                offset += 2;
                return value.ToString(CultureInfo.InvariantCulture);
            }
            case OperandType.InlineI:
            {
                var value = BitConverter.ToInt32(code, offset);
                offset += 4;
                return value.ToString(CultureInfo.InvariantCulture);
            }
            case OperandType.InlineI8:
            {
                var value = BitConverter.ToInt64(code, offset);
                offset += 8;
                return value.ToString(CultureInfo.InvariantCulture);
            }
            case OperandType.ShortInlineR:
            {
                var value = BitConverter.ToUInt32(code, offset);
                offset += 4;
                return $"0x{value:x8}";
            }
            case OperandType.InlineR:
            {
                var value = BitConverter.ToUInt64(code, offset);
                offset += 8;
                return $"0x{value:x16}";
            }
            case OperandType.ShortInlineBrTarget:
            {
                var delta = (sbyte)code[offset];
                offset += 1;
                return $"IL_{offset + delta:x4}";
            }
            case OperandType.InlineBrTarget:
            {
                var delta = BitConverter.ToInt32(code, offset);
                offset += 4;
                return $"IL_{offset + delta:x4}";
            }
            case OperandType.InlineSwitch:
            {
                var count = BitConverter.ToInt32(code, offset);
                offset += 4;
                var deltas = new int[count];
                for (var i = 0; i < count; i++)
                {
                    deltas[i] = BitConverter.ToInt32(code, offset);
                    offset += 4;
                }

                var next = offset;
                var targets = deltas.Select(d => $"IL_{next + d:x4}");
                return $"({string.Join(",", targets)})";
            }
            case OperandType.InlineString:
            {
                var token = BitConverter.ToInt32(code, offset);
                offset += 4;
                var handle = MetadataTokens.UserStringHandle(token);
                return Quote(reader.GetUserString(handle));
            }
            default:
            {
                var token = BitConverter.ToInt32(code, offset);
                offset += 4;
                return TokenName(MetadataTokens.EntityHandle(token));
            }
        }
    }

    internal string TokenName(EntityHandle handle)
    {
        if (handle.IsNil)
        {
            return "-";
        }

        switch (handle.Kind)
        {
            case HandleKind.TypeDefinition:
            case HandleKind.TypeReference:
            case HandleKind.TypeSpecification:
                return TypeName(handle);
            case HandleKind.MethodDefinition:
            {
                var method = reader.GetMethodDefinition((MethodDefinitionHandle)handle);
                return $"{FullName(method.GetDeclaringType())}::{reader.GetString(method.Name)}";
            }
            case HandleKind.FieldDefinition:
            {
                var field = reader.GetFieldDefinition((FieldDefinitionHandle)handle);
                return $"{FullName(field.GetDeclaringType())}::{reader.GetString(field.Name)}";
            }
            case HandleKind.MemberReference:
            {
                var member = reader.GetMemberReference((MemberReferenceHandle)handle);
                return $"{TokenName(member.Parent)}::{reader.GetString(member.Name)}";
            }
            case HandleKind.MethodSpecification:
            {
                var spec = reader.GetMethodSpecification((MethodSpecificationHandle)handle);
                var args = spec.DecodeSignature(new TypeNames(this), null!);
                return $"{TokenName(spec.Method)}<{string.Join(", ", args)}>";
            }
            case HandleKind.StandaloneSignature:
                return $"StandAloneSig[{MetadataTokens.GetRowNumber(handle)}]";
            case HandleKind.ModuleReference:
            {
                var module = reader.GetModuleReference((ModuleReferenceHandle)handle);
                return $"[.module {reader.GetString(module.Name)}]";
            }
            case HandleKind.AssemblyReference:
            {
                var assembly = reader.GetAssemblyReference((AssemblyReferenceHandle)handle);
                return $"[{reader.GetString(assembly.Name)}]";
            }
            default:
                return $"{handle.Kind}[{MetadataTokens.GetRowNumber(handle)}]";
        }
    }

    internal string TypeName(EntityHandle handle)
    {
        if (handle.IsNil)
        {
            return "-";
        }

        switch (handle.Kind)
        {
            case HandleKind.TypeDefinition:
                return FullName((TypeDefinitionHandle)handle);
            case HandleKind.TypeReference:
            {
                var reference = reader.GetTypeReference((TypeReferenceHandle)handle);
                var name = Qualify(
                    reader.GetString(reference.Namespace),
                    reader.GetString(reference.Name));
                return reference.ResolutionScope.Kind switch
                {
                    HandleKind.AssemblyReference =>
                        $"[{reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)reference.ResolutionScope).Name)}]{name}",
                    HandleKind.ModuleReference =>
                        $"[.module {reader.GetString(reader.GetModuleReference((ModuleReferenceHandle)reference.ResolutionScope).Name)}]{name}",
                    HandleKind.TypeReference => $"{TypeName(reference.ResolutionScope)}/{name}",
                    _ => name,
                };
            }
            case HandleKind.TypeSpecification:
            {
                var spec = reader.GetTypeSpecification((TypeSpecificationHandle)handle);
                return spec.DecodeSignature(new TypeNames(this), null!);
            }
            default:
                return TokenName(handle);
        }
    }

    internal string FullName(TypeDefinitionHandle handle)
    {
        var type = reader.GetTypeDefinition(handle);
        var name = Qualify(reader.GetString(type.Namespace), reader.GetString(type.Name));
        var declaring = type.GetDeclaringType();
        return declaring.IsNil ? name : $"{FullName(declaring)}/{name}";
    }

    internal static string Qualify(string ns, string name) =>
        string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

    internal static string MethodSignature(MethodSignature<string> signature)
    {
        var prefix = new StringBuilder();
        if (signature.Header.IsInstance)
        {
            prefix.Append("instance ");
        }

        if (signature.Header.HasExplicitThis)
        {
            prefix.Append("explicit ");
        }

        prefix.Append(signature.Header.CallingConvention switch
        {
            SignatureCallingConvention.VarArgs => "vararg ",
            SignatureCallingConvention.CDecl => "unmanaged cdecl ",
            SignatureCallingConvention.StdCall => "unmanaged stdcall ",
            SignatureCallingConvention.ThisCall => "unmanaged thiscall ",
            SignatureCallingConvention.FastCall => "unmanaged fastcall ",
            SignatureCallingConvention.Unmanaged => "unmanaged ",
            _ => string.Empty,
        });

        var parameters = signature.ParameterTypes.ToList();
        if (signature.RequiredParameterCount < parameters.Count)
        {
            parameters.Insert(signature.RequiredParameterCount, "...");
        }

        var generics = signature.GenericParameterCount > 0
            ? $"<{signature.GenericParameterCount}>"
            : string.Empty;
        return $"{prefix}{signature.ReturnType} {generics}({string.Join(", ", parameters)})";
    }

    private static string Bool(bool value) => value ? "true" : "false";

    internal static string Quote(string value)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in value)
        {
            sb.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when c < 0x20 || c > 0x7E => $"\\u{(int)c:x4}",
                _ => c.ToString(),
            });
        }

        return sb.Append('"').ToString();
    }

    /// <summary>The properties and events of a type, with their accessors.</summary>
    /// <remarks>
    /// MethodSemantics has no row enumeration here, so it is reached the way
    /// this reader can reach it: through the accessors of each member.
    /// </remarks>
    private void DumpMembers(TypeDefinition type)
    {
        foreach (var handle in type.GetProperties())
        {
            var property = reader.GetPropertyDefinition(handle);
            var signature = property.DecodeSignature(new TypeNames(this), null!);
            var parameters = string.Join(", ", signature.ParameterTypes);
            var sig = $"{(signature.Header.IsInstance ? "instance " : "")}{signature.ReturnType} ({parameters})";
            var accessors = property.GetAccessors();
            Line($"  property {MetadataTokens.GetRowNumber(handle)} " +
                 $"{Quote(reader.GetString(property.Name))} sig={sig} " +
                 $"flags=0x{(int)property.Attributes:x4} " +
                 $"getter=0x{Token(accessors.Getter):x8} setter=0x{Token(accessors.Setter):x8}");
        }

        foreach (var handle in type.GetEvents())
        {
            var @event = reader.GetEventDefinition(handle);
            var accessors = @event.GetAccessors();
            Line($"  event {MetadataTokens.GetRowNumber(handle)} " +
                 $"{Quote(reader.GetString(@event.Name))} type=0x{Token(@event.Type):x8} " +
                 $"flags=0x{(int)@event.Attributes:x4} " +
                 $"adder=0x{Token(accessors.Adder):x8} remover=0x{Token(accessors.Remover):x8} " +
                 $"raiser=0x{Token(accessors.Raiser):x8}");
        }
    }

    /// <summary>A handle as a raw metadata token; nil becomes 0.</summary>
    private int Token(EntityHandle handle) =>
        handle.IsNil ? 0 : MetadataTokens.GetToken(reader, handle);

    private int BlobLength(BlobHandle handle) =>
        handle.IsNil ? 0 : reader.GetBlobReader(handle).Length;

    private static string Hex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    /// <summary>Every table the type walk does not already cover.</summary>
    private void DumpRows()
    {
        // InterfaceImplementation does not carry its class, so build the
        // mapping from the types that declare them.
        var interfaceClass = new Dictionary<int, int>();
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(typeHandle);
            foreach (var implHandle in type.GetInterfaceImplementations())
            {
                interfaceClass[MetadataTokens.GetRowNumber(implHandle)] = Token(typeHandle);
            }
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.InterfaceImpl); rid++)
        {
            var handle = MetadataTokens.InterfaceImplementationHandle(rid);
            var row = reader.GetInterfaceImplementation(handle);
            interfaceClass.TryGetValue(rid, out var declaringClass);
            Line($"row InterfaceImpl {rid} class=0x{declaringClass:x8} " +
                 $"interface=0x{Token(row.Interface):x8}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.MemberRef); rid++)
        {
            var handle = MetadataTokens.MemberReferenceHandle(rid);
            var row = reader.GetMemberReference(handle);
            var sig = row.GetKind() == MemberReferenceKind.Field
                ? row.DecodeFieldSignature(new TypeNames(this), null!)
                : MethodSignature(row.DecodeMethodSignature(new TypeNames(this), null!));
            Line($"row MemberRef {rid} class=0x{Token(row.Parent):x8} " +
                 $"name={Quote(reader.GetString(row.Name))} sig={sig}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.Constant); rid++)
        {
            var handle = MetadataTokens.ConstantHandle(rid);
            var row = reader.GetConstant(handle);
            Line($"row Constant {rid} type=0x{(byte)row.TypeCode:x2} " +
                 $"parent=0x{Token(row.Parent):x8} value={Hex(reader.GetBlobBytes(row.Value))}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.CustomAttribute); rid++)
        {
            var handle = MetadataTokens.CustomAttributeHandle(rid);
            var row = reader.GetCustomAttribute(handle);
            Line($"row CustomAttribute {rid} parent=0x{Token(row.Parent):x8} " +
                 $"ctor=0x{Token(row.Constructor):x8} value={BlobLength(row.Value)}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.DeclSecurity); rid++)
        {
            var handle = MetadataTokens.DeclarativeSecurityAttributeHandle(rid);
            var row = reader.GetDeclarativeSecurityAttribute(handle);
            Line($"row DeclSecurity {rid} action=0x{(int)row.Action:x4} " +
                 $"parent=0x{Token(row.Parent):x8} permission={BlobLength(row.PermissionSet)}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.StandAloneSig); rid++)
        {
            var handle = MetadataTokens.StandaloneSignatureHandle(rid);
            var row = reader.GetStandaloneSignature(handle);
            Line($"row StandAloneSig {rid} len={BlobLength(row.Signature)}");
        }

        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(typeHandle);
            foreach (var implHandle in type.GetMethodImplementations())
            {
                var row = reader.GetMethodImplementation(implHandle);
                Line($"row MethodImpl {MetadataTokens.GetRowNumber(implHandle)} " +
                     $"class=0x{Token(row.Type):x8} body=0x{Token(row.MethodBody):x8} " +
                     $"decl=0x{Token(row.MethodDeclaration):x8}");
            }
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.ModuleRef); rid++)
        {
            var handle = MetadataTokens.ModuleReferenceHandle(rid);
            var row = reader.GetModuleReference(handle);
            Line($"row ModuleRef {rid} name={Quote(reader.GetString(row.Name))}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.TypeSpec); rid++)
        {
            var handle = MetadataTokens.TypeSpecificationHandle(rid);
            var row = reader.GetTypeSpecification(handle);
            Line($"row TypeSpec {rid} sig={row.DecodeSignature(new TypeNames(this), null!)}");
        }

        if (reader.IsAssembly)
        {
            var assembly = reader.GetAssemblyDefinition();
            var version = assembly.Version;
            Line($"row Assembly 1 name={Quote(reader.GetString(assembly.Name))} " +
                 $"version={version.Major}.{version.Minor}.{version.Build}.{version.Revision} " +
                 $"flags=0x{(int)assembly.Flags:x8} hashalg=0x{(int)assembly.HashAlgorithm:x8} " +
                 $"culture={Quote(reader.GetString(assembly.Culture))} " +
                 $"publickey={BlobLength(assembly.PublicKey)}");
        }

        foreach (var handle in reader.AssemblyReferences)
        {
            var row = reader.GetAssemblyReference(handle);
            var version = row.Version;
            Line($"row AssemblyRef {MetadataTokens.GetRowNumber(handle)} " +
                 $"name={Quote(reader.GetString(row.Name))} " +
                 $"version={version.Major}.{version.Minor}.{version.Build}.{version.Revision} " +
                 $"flags=0x{(int)row.Flags:x8} culture={Quote(reader.GetString(row.Culture))} " +
                 $"publickey={BlobLength(row.PublicKeyOrToken)} hash={BlobLength(row.HashValue)}");
        }

        foreach (var handle in reader.AssemblyFiles)
        {
            var row = reader.GetAssemblyFile(handle);
            var flags = row.ContainsMetadata ? 0 : 1;
            Line($"row File {MetadataTokens.GetRowNumber(handle)} flags=0x{flags:x8} " +
                 $"name={Quote(reader.GetString(row.Name))} hash={BlobLength(row.HashValue)}");
        }

        foreach (var handle in reader.ExportedTypes)
        {
            var row = reader.GetExportedType(handle);
            Line($"row ExportedType {MetadataTokens.GetRowNumber(handle)} " +
                 $"flags=0x{(int)row.Attributes:x8} typedefid=0x{row.GetTypeDefinitionId():x8} " +
                 $"name={Quote(reader.GetString(row.Name))} " +
                 $"namespace={Quote(reader.GetString(row.Namespace))} " +
                 $"implementation=0x{Token(row.Implementation):x8}");
        }

        foreach (var handle in reader.ManifestResources)
        {
            var row = reader.GetManifestResource(handle);
            Line($"row ManifestResource {MetadataTokens.GetRowNumber(handle)} " +
                 $"offset=0x{row.Offset:x8} flags=0x{(int)row.Attributes:x8} " +
                 $"name={Quote(reader.GetString(row.Name))} " +
                 $"implementation=0x{Token(row.Implementation):x8}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.GenericParam); rid++)
        {
            var handle = MetadataTokens.GenericParameterHandle(rid);
            var row = reader.GetGenericParameter(handle);
            Line($"row GenericParam {rid} number={row.Index} " +
                 $"flags=0x{(int)row.Attributes:x4} owner=0x{Token(row.Parent):x8} " +
                 $"name={Quote(reader.GetString(row.Name))}");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.MethodSpec); rid++)
        {
            var handle = MetadataTokens.MethodSpecificationHandle(rid);
            var row = reader.GetMethodSpecification(handle);
            var args = string.Join(", ", row.DecodeSignature(new TypeNames(this), null!));
            Line($"row MethodSpec {rid} method=0x{Token(row.Method):x8} args=<{args}>");
        }

        for (var rid = 1; rid <= reader.GetTableRowCount(TableIndex.GenericParamConstraint); rid++)
        {
            var handle = MetadataTokens.GenericParameterConstraintHandle(rid);
            var row = reader.GetGenericParameterConstraint(handle);
            Line($"row GenericParamConstraint {rid} owner=0x{Token(row.Parameter):x8} " +
                 $"constraint=0x{Token(row.Type):x8}");
        }
    }

    private void Line(string text) => output.Append(text).Append('\n');
}

/// <summary>Renders signature types in the same ILAsm-ish form as cildec.</summary>
internal sealed class TypeNames(Dumper dumper) : ISignatureTypeProvider<string, object>
{
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Void => "void",
        PrimitiveTypeCode.Boolean => "bool",
        PrimitiveTypeCode.Char => "char",
        PrimitiveTypeCode.SByte => "int8",
        PrimitiveTypeCode.Byte => "uint8",
        PrimitiveTypeCode.Int16 => "int16",
        PrimitiveTypeCode.UInt16 => "uint16",
        PrimitiveTypeCode.Int32 => "int32",
        PrimitiveTypeCode.UInt32 => "uint32",
        PrimitiveTypeCode.Int64 => "int64",
        PrimitiveTypeCode.UInt64 => "uint64",
        PrimitiveTypeCode.Single => "float32",
        PrimitiveTypeCode.Double => "float64",
        PrimitiveTypeCode.String => "string",
        PrimitiveTypeCode.TypedReference => "typedref",
        PrimitiveTypeCode.IntPtr => "native int",
        PrimitiveTypeCode.UIntPtr => "native uint",
        PrimitiveTypeCode.Object => "object",
        _ => throw new NotSupportedException($"primitive {typeCode}"),
    };

    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
        $"{Keyword(rawTypeKind)} {dumper.FullName(handle)}";

    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
        $"{Keyword(rawTypeKind)} {dumper.TypeName(handle)}";

    public string GetTypeFromSpecification(
        MetadataReader reader,
        object genericContext,
        TypeSpecificationHandle handle,
        byte rawTypeKind) => dumper.TypeName(handle);

    public string GetSZArrayType(string elementType) => $"{elementType}[]";

    public string GetPointerType(string elementType) => $"{elementType}*";

    public string GetByReferenceType(string elementType) => $"{elementType}&";

    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) =>
        $"{genericType}<{string.Join(", ", typeArguments)}>";

    public string GetArrayType(string elementType, ArrayShape shape)
    {
        var parts = new List<string>();
        for (var i = 0; i < shape.Rank; i++)
        {
            var lo = i < shape.LowerBounds.Length ? shape.LowerBounds[i] : (int?)null;
            var size = i < shape.Sizes.Length ? shape.Sizes[i] : (int?)null;
            parts.Add((lo, size) switch
            {
                (int l, int s) => $"{l}...{(long)l + s - 1}",
                (int l, null) => $"{l}...",
                (null, int s) => $"{s}",
                _ => string.Empty,
            });
        }

        return $"{elementType}[{string.Join(",", parts)}]";
    }

    public string GetGenericMethodParameter(object genericContext, int index) => $"!!{index}";

    public string GetGenericTypeParameter(object genericContext, int index) => $"!{index}";

    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) =>
        $"{unmodifiedType} {(isRequired ? "modreq" : "modopt")}({Strip(modifier)})";

    public string GetPinnedType(string elementType) => $"{elementType} pinned";

    public string GetFunctionPointerType(MethodSignature<string> signature) =>
        $"method {Dumper.MethodSignature(signature)}";

    private static string Keyword(byte rawTypeKind) => rawTypeKind switch
    {
        0x11 => "valuetype",
        0x12 => "class",
        // The signature did not say; cildec only ever sees an explicit
        // CLASS or VALUETYPE byte, so this branch marks a decode this tool
        // could not classify.
        _ => "class",
    };

    /// <summary>Custom-modifier types are printed without a class/valuetype keyword.</summary>
    private static string Strip(string modifier)
    {
        foreach (var keyword in new[] { "class ", "valuetype " })
        {
            if (modifier.StartsWith(keyword, StringComparison.Ordinal))
            {
                return modifier[keyword.Length..];
            }
        }

        return modifier;
    }
}
