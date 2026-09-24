using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;

namespace WinSight.Mcp.Tests;

/// <summary>
/// A conservative call graph over the IL of WinSight's own assemblies. From a set of roots it follows
/// every <c>call</c>, <c>callvirt</c>, <c>newobj</c>, <c>ldftn</c>, <c>ldvirtftn</c> and method
/// <c>ldtoken</c>; the <c>MoveNext</c> of each async or iterator state machine; type initialisers;
/// and, for a virtual or interface call on a WinSight method, every WinSight override or
/// implementation (class-hierarchy analysis). A WinSight type that is constructed, or passed as a
/// generic argument (dependency injection, <c>typeof</c>), brings its virtual methods too, since
/// framework code may call them. Framework methods are not walked: a WinSight method reachable only
/// through a framework callback therefore has to enter through one of those rules.
/// </summary>
/// <remarks>
/// <b>What it is not (RA-06).</b> A finite walk of WinSight's IL, not a proof about every future side
/// effect. It does not enter the framework, so what a framework method does is judged at the call
/// site: every call leaving WinSight is recorded in <see cref="ExternalCalls"/> and every WinSight
/// P/Invoke reached in <see cref="NativeCalls"/>, for the tests to hold against a denylist of mutating
/// framework APIs and a reviewed list of native functions. Reflection with a computed name, a
/// delegate built outside the walk, or native code calling back are outside it.
/// </remarks>
internal sealed class IlCallGraph
{
    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(field => (OpCode)field.GetValue(null)!)
        .ToDictionary(code => code.Value);

    private readonly Type[] _winSightTypes;
    private readonly Func<MethodBase, bool> _stopAt;
    private readonly Queue<MethodBase> _pending = new();
    private readonly Dictionary<MethodBase, MethodBase?> _parents = [];
    private readonly HashSet<Type> _instantiated = [];

    /// <param name="winSightAssemblies">The assemblies whose types the class-hierarchy analysis considers.</param>
    /// <param name="stopAt">
    /// Methods reached but not entered: reviewed owners of a known side effect, so a walk can hold
    /// everything else to a stricter rule.
    /// </param>
    public IlCallGraph(IEnumerable<Assembly> winSightAssemblies, Func<MethodBase, bool>? stopAt = null)
    {
        _winSightTypes = winSightAssemblies.SelectMany(LoadableTypes).ToArray();
        _stopAt = stopAt ?? (_ => false);
    }

    /// <summary>Tokens that could not be resolved. Each one is a hole in the proof, so callers assert it empty.</summary>
    public List<string> Unresolved { get; } = [];

    public IReadOnlyCollection<MethodBase> Reached => _parents.Keys;

    /// <summary>
    /// Every call from a reached WinSight method to a method outside WinSight, with its caller: the
    /// point where the walk stops and a side effect has to be recognised by name.
    /// </summary>
    public HashSet<(MethodBase Caller, MethodBase Target)> ExternalCalls { get; } = [];

    /// <summary>The WinSight-declared native functions (<c>DllImport</c>, and <c>LibraryImport</c>'s inner stub) reached.</summary>
    public IEnumerable<MethodBase> NativeCalls =>
        _parents.Keys.Where(method => (method.Attributes & MethodAttributes.PinvokeImpl) != 0);

    /// <summary>WinSight's own code: the <c>WinSight.*</c> libraries and the <c>winsight</c> CLI.</summary>
    public static bool IsWinSight(Assembly assembly) => IsWinSight(assembly.GetName());

    public static bool IsWinSight(AssemblyName name) => name.Name is { } simple
        && (simple.StartsWith("WinSight.", StringComparison.Ordinal) || simple == "winsight");

    /// <summary>Walks everything reachable from <paramref name="roots"/>.</summary>
    public IlCallGraph Walk(IEnumerable<MethodBase> roots)
    {
        foreach (var root in roots)
        {
            Enqueue(root, parent: null);
        }
        while (_pending.TryDequeue(out var method))
        {
            Visit(method);
        }
        return this;
    }

    /// <summary>The call chain from a root to <paramref name="method"/>, for a readable failure.</summary>
    public string PathTo(MethodBase method)
    {
        var chain = new List<string>();
        for (MethodBase? step = method; step is not null && chain.Count < 64; step = _parents[step])
        {
            chain.Add(Describe(step));
        }
        chain.Reverse();
        return string.Join(" -> ", chain);
    }

    public static string Describe(MethodBase method) =>
        $"{method.DeclaringType?.FullName}.{method.Name}";

    private static IEnumerable<Type> LoadableTypes(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.OfType<Type>();
        }
    }

    private void Enqueue(MethodBase method, MethodBase? parent)
    {
        if (method.DeclaringType is null || !IsWinSight(method.Module.Assembly))
        {
            return;
        }
        // Walk the definition, not an instantiation: one body per method, resolved in its own context.
        // A method the runtime supplies (no metadata row, such as a delegate's Invoke) is its own definition.
        var definition = (method.MetadataToken & 0x00FFFFFF) == 0
            ? method
            : method.Module.ResolveMethod(method.MetadataToken)!;
        if (_parents.TryAdd(definition, parent))
        {
            _pending.Enqueue(definition);
        }
    }

    private void Visit(MethodBase method)
    {
        if (_stopAt(method))
        {
            return;
        }
        var type = method.DeclaringType!;
        if (type.TypeInitializer is { } initializer)
        {
            Enqueue(initializer, method);
        }
        if (method.GetCustomAttribute<StateMachineAttribute>() is { } stateMachine)
        {
            foreach (var moveNext in stateMachine.StateMachineType.GetMethods(Declared))
            {
                Enqueue(moveNext, method);
            }
        }
        if (method.IsConstructor && !method.IsStatic)
        {
            MarkInstantiated(type, method);
        }
        var body = method.GetMethodBody()?.GetILAsByteArray();
        if (body is not null)
        {
            WalkBody(method, body);
        }
    }

    private void WalkBody(MethodBase method, byte[] il)
    {
        var typeArguments = method.DeclaringType!.IsGenericType ? method.DeclaringType.GetGenericArguments() : null;
        var methodArguments = method.IsGenericMethod ? method.GetGenericArguments() : null;
        var position = 0;
        while (position < il.Length)
        {
            var value = (short)il[position++];
            if (value == 0xFE)
            {
                value = unchecked((short)(0xFE00 | il[position++]));
            }
            if (!OpCodesByValue.TryGetValue(value, out var code))
            {
                Unresolved.Add($"{Describe(method)}: unknown opcode 0x{value:X4} at {position}");
                return;
            }
            var operandStart = position;
            position += OperandSize(code, il, position);
            if (code.OperandType is OperandType.InlineMethod or OperandType.InlineTok
                or OperandType.InlineField or OperandType.InlineType)
            {
                var token = BitConverter.ToInt32(il, operandStart);
                Follow(method, code, token, typeArguments, methodArguments);
            }
        }
    }

    private static int OperandSize(OpCode code, byte[] il, int position) => code.OperandType switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => 4 + (4 * BitConverter.ToInt32(il, position)),
        _ => 4,
    };

    private void Follow(MethodBase method, OpCode code, int token, Type[]? typeArguments, Type[]? methodArguments)
    {
        MemberInfo? member;
        try
        {
            member = method.Module.ResolveMember(token, typeArguments, methodArguments);
        }
        catch (Exception ex) when (ex is ArgumentException or TypeLoadException or FileNotFoundException
            or MissingMemberException or BadImageFormatException)
        {
            Unresolved.Add($"{Describe(method)}: {code.Name} 0x{token:X8} ({ex.GetType().Name}: {ex.Message})");
            return;
        }
        switch (member)
        {
            case MethodBase target:
                FollowMethod(method, code, target);
                break;
            case FieldInfo field when field.IsStatic && field.DeclaringType?.TypeInitializer is { } initializer:
                Enqueue(initializer, method);
                break;
            case Type type when code == OpCodes.Ldtoken:
                MarkInstantiated(type, method);
                break;
        }
    }

    private void FollowMethod(MethodBase caller, OpCode code, MethodBase target)
    {
        if (code != OpCodes.Ldtoken && !IsWinSight(target.Module.Assembly))
        {
            ExternalCalls.Add((caller, target));
        }
        Enqueue(target, caller);
        if (target.IsGenericMethod)
        {
            foreach (var argument in target.GetGenericArguments())
            {
                MarkInstantiated(argument, caller);
            }
        }
        if (target.DeclaringType is { IsGenericType: true } declaring)
        {
            foreach (var argument in declaring.GetGenericArguments())
            {
                MarkInstantiated(argument, caller);
            }
        }
        if ((code == OpCodes.Callvirt || code == OpCodes.Ldvirtftn || code == OpCodes.Ldftn)
            && target is MethodInfo { IsVirtual: true } virtualTarget
            && IsWinSight(target.Module.Assembly))
        {
            foreach (var implementation in Implementations(virtualTarget))
            {
                Enqueue(implementation, caller);
            }
        }
    }

    private void MarkInstantiated(Type type, MethodBase cause)
    {
        if (type.IsGenericParameter || !IsWinSight(type.Assembly))
        {
            return;
        }
        var definition = type.IsGenericType ? type.GetGenericTypeDefinition() : type;
        if (!_instantiated.Add(definition))
        {
            return;
        }
        foreach (var member in FrameworkCallbacks(definition))
        {
            Enqueue(member, cause);
        }
        foreach (var constructor in definition.GetConstructors(Declared))
        {
            Enqueue(constructor, cause);
        }
    }

    /// <summary>
    /// The methods of <paramref name="type"/> that framework code can call: overrides of a framework
    /// virtual (<c>ToString</c>, <c>Dispose(bool)</c>...) and implementations of a framework interface
    /// (<c>IDisposable</c>, <c>IComparer&lt;T&gt;</c>...). A method that only implements a WinSight
    /// contract is reached, if at all, through a WinSight call site that the walk already follows.
    /// </summary>
    private static IEnumerable<MethodInfo> FrameworkCallbacks(Type type)
    {
        foreach (var method in type.GetMethods(Declared).Where(m => m.IsVirtual && !m.IsAbstract))
        {
            if (!IsWinSight(method.GetBaseDefinition().Module.Assembly))
            {
                yield return method;
            }
        }
        if (type.IsInterface)
        {
            yield break;
        }
        foreach (var contract in type.GetInterfaces().Where(i => !IsWinSight(i.Assembly)))
        {
            InterfaceMapping map;
            try
            {
                map = type.GetInterfaceMap(contract);
            }
            catch (ArgumentException)
            {
                continue;
            }
            foreach (var target in map.TargetMethods.Where(m => m.DeclaringType == type))
            {
                yield return target;
            }
        }
    }

    private IEnumerable<MethodBase> Implementations(MethodInfo target)
    {
        var declaring = Definition(target.DeclaringType!);
        if (declaring.IsInterface)
        {
            foreach (var type in _winSightTypes.Where(t => !t.IsInterface))
            {
                foreach (var implemented in type.GetInterfaces().Where(i => Definition(i) == declaring))
                {
                    InterfaceMapping map;
                    try
                    {
                        map = type.GetInterfaceMap(implemented);
                    }
                    catch (ArgumentException)
                    {
                        continue;
                    }
                    for (var i = 0; i < map.InterfaceMethods.Length; i++)
                    {
                        if (map.InterfaceMethods[i].MetadataToken == target.MetadataToken)
                        {
                            yield return map.TargetMethods[i];
                        }
                    }
                }
            }
            yield break;
        }
        var root = target.GetBaseDefinition();
        foreach (var type in _winSightTypes.Where(t => DerivesFrom(t, declaring)))
        {
            foreach (var candidate in type.GetMethods(Declared).Where(m => m.IsVirtual))
            {
                var candidateRoot = candidate.GetBaseDefinition();
                if (candidateRoot.Module == root.Module && candidateRoot.MetadataToken == root.MetadataToken)
                {
                    yield return candidate;
                }
            }
        }
    }

    private static Type Definition(Type type) => type.IsGenericType ? type.GetGenericTypeDefinition() : type;

    private static bool DerivesFrom(Type type, Type declaring)
    {
        for (var current = type.BaseType; current is not null; current = current.BaseType)
        {
            if (Definition(current) == declaring)
            {
                return true;
            }
        }
        return false;
    }
}
