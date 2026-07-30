# Coding standards

The rules this codebase actually enforces, not a wish list. Each one exists because breaking it has
cost something here, and most are checked by CI rather than by review.

## Async and concurrency

**Never `.Result`, `.Wait()` or `.GetAwaiter().GetResult()`.** These block a thread on work that has
not finished, and under thread-pool starvation they deadlock. Both patterns were found in the
privileged service and both were removed: one was performing synchronous file I/O inside an ETW trace
callback, where a slow consumer makes the kernel drop events.

**A loop that runs until shutdown owns a dedicated thread, never a pool thread.** A work item that
never returns holds its pool thread for the life of the process, and the pool grows slowly once
saturated. This failed a release build before it was fixed.

Every public async method takes a `CancellationToken` as its last parameter with a default, and async
methods end in `Async`.

```csharp
public async Task<Data> GetDataAsync(Guid id, CancellationToken cancellationToken = default) =>
    await _service.FetchAsync(id, cancellationToken);
```

## Immutability

`record` for DTOs and value objects, `with` expressions for modification, `init` properties and
immutable collections. Never mutate a method parameter or shared state.

```csharp
public sealed record UserDto(Guid Id, string Email, string FirstName);

public static UserDto Rename(UserDto user, string firstName) => user with { FirstName = firstName };
```

## Null safety

`<Nullable>enable</Nullable>` is set solution-wide in `Directory.Build.props` and
`TreatWarningsAsErrors` is on, so an unannotated reference is a build failure rather than a review
comment. Use `?`, `??` and `?.` deliberately.

## Types

Records for immutable data, classes for entities with identity or lifecycle, interfaces at service
boundaries. Sealed by default; unseal only when inheritance is intended. Primary constructors where
they read well.

## Reporting honestly

This is a security tool, so the rule that matters most is about what the code is allowed to claim.

**An unreadable value is not a verdict.** "We could not determine this" and "this is off" are
different facts and must stay different in the type system, not collapse into whichever is easier to
render. Unknown states get their own enum member and their own message. A reader that guesses is
worse than one that admits a gap, because the guess is trusted.

**Undocumented encodings are not a source of truth.** Prefer a documented API even when a widely
copied bit-layout appears to work. When no documented alternative exists, say so in the code and let
unrecognised values stay unrecognised.

## Naming

PascalCase for public members and types, camelCase for locals and parameters, `Is`/`Has`/`Can` for
booleans.

## Quality gates

Run in this order, cheapest first, matching CI:

```bash
dotnet format winsight.sln --verify-no-changes
```
```bash
dotnet build winsight.sln -c Release
```
```bash
dotnet test winsight.sln --no-build -c Release
```

CI additionally enforces:

- **80% line coverage** on every detection-engine library, and on the hand-written half of the
  privileged service. The native WFP and SCM boundary is excluded because the VM protocol qualifies it
  instead, which is evidence of a different kind rather than an absence of evidence.
- The full suite on **three Windows images**, including native Arm64. Arm64 is tested on every pull
  request rather than only at tag time, because a defect found at tag time is found at the worst
  possible moment.
- Formatting, a dependency vulnerability audit, and the read-only Controlled Folder Access provider
  contract against the built CLI.

## Before requesting review

- No blocking-async pattern, no loop parked on the thread pool
- Nullable annotations explicit, no mutation of parameters or shared state
- No claim in a message that the data does not support
- Tests cover the failure paths, not only the happy one
- `dotnet format` clean

## References

- [.NET coding conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions)
- [Async/await best practices](https://learn.microsoft.com/en-us/archive/msdn-magazine/2013/march/async-await-best-practices-in-asynchronous-programming)
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for how the projects fit together
- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) for what is deliberately out of scope
