# WinSight — Modern C# Project Standards (2025)

This project enforces **modern C# best practices** focusing on safety, performance, and maintainability.

## 🚀 Quick Standards

### Async/Concurrency (CRITICAL)
- **NEVER** use `.Result`, `.Wait()`, `.GetAwaiter().GetResult()` — causes deadlocks
- Always `await` async operations
- All public async methods have `CancellationToken` parameter (last, with default)
- Async methods end with `Async` suffix

```csharp
// ✅ Correct
public async Task<Data> GetDataAsync(Guid id, CancellationToken cancellationToken = default)
{
    return await _service.FetchAsync(id, cancellationToken);
}

// ❌ Wrong
var data = _service.FetchAsync(id).Result;  // DEADLOCK!
```

### Immutability (CRITICAL)
- Use `record` for immutable DTOs and value objects
- Never mutate method parameters or shared state
- Use `with` expressions for modifications
- Prefer `init` properties and `ImmutableList<T>`

```csharp
// ✅ Correct — immutable record
public sealed record UserDto(Guid Id, string Email, string FirstName);

public static UserDto Rename(UserDto user, string firstName) =>
    user with { FirstName = firstName };

// ❌ Wrong — mutation
user.FirstName = "New Name";  // Don't mutate
```

### Null Safety
- Enable `#nullable enable` in .csproj or file header
- Use `string?` for nullable types
- Use null-coalescing (`??`) and null-conditional (`?.`) operators

```csharp
// ✅ Explicit nullable annotation
public string? OptionalName { get; set; }

var email = user.Email ?? "unknown@example.com";
string? name = order?.Customer?.Name;
```

### Types
- **Records** for DTOs, value objects, immutable models
- **Classes** for entities with identity/lifecycle
- **Interfaces** for service boundaries
- Sealed classes by default (only unsealed if inheritance is intended)
- Primary constructors (C# 12+)

```csharp
// ✅ Modern record with primary constructor
public sealed record Order(Guid Id, string CustomerId);

// ✅ Primary constructor class
public sealed class OrderService(IRepository<Order> repository)
{
    public async Task<Order> CreateAsync(Order order, CancellationToken ct)
    {
        return await repository.AddAsync(order, ct);
    }
}
```

### Performance
- Use `ValueTask<T>` for hot paths (after profiling)
- Avoid unnecessary allocations
- No premature optimization — profile first

### Naming
- PascalCase: public members, types, methods
- camelCase: local variables, method parameters
- ALL_CAPS: constants
- Boolean properties: `IsActive`, `HasItems`, `CanProcess`

## 📋 Quality Gates

### Before Committing
- [ ] No async deadlock patterns (`.Result`, `.Wait()`)
- [ ] Nullable types properly annotated
- [ ] No mutation of parameters or shared state
- [ ] 80%+ test coverage
- [ ] Code formatted (`dotnet format`)

### Code Review Checklist
See [Code Review Standards](~/.claude/rules/csharp/coding-style.md) for complete checklist.

## 📚 References

- **Rules:** `~/.claude/rules/csharp/` — Complete standards for all aspects
  - `coding-style.md` — Types, nullability, immutability, formatting
  - `async.md` — Async/await patterns, cancellation, performance
  - `patterns.md` — Clean Architecture, DDD, DI, Result pattern
  - `data-access.md` — Entity Framework Core, LINQ optimization, N+1 prevention
  - `logging.md` — Structured logging with ILogger/Serilog, security
  - `solid.md` — SOLID principles for design (SRP, OCP, LSP, ISP, DIP)
  - `testing.md` — Unit/integration testing standards
  - `security.md` — Security checklist

- **Memory (auto-loaded):** Project-specific C# best practices from prior sessions

- **External:**
  - [Microsoft .NET Coding Conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions)
  - [Async/Await Best Practices](https://learn.microsoft.com/en-us/archive/msdn-magazine/2013/march/async-await-best-practices-in-asynchronous-programming)
  - [Clean Architecture in .NET](https://milanjovanovic.tech/blog/clean-architecture-dotnet)

## RTK (Token Optimization)

For token-efficient commands:
```bash
rtk git status           # Compact git status
rtk dotnet test          # Test failures only
rtk dotnet build         # Build errors only
```

See `~/.claude/CLAUDE.md` for full RTK reference.
