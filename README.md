# SM-ThreadLimiter

SM-ThreadLimiter is a Scrap Mechanic performance-mod experiment. Its DLL replaces the Concurrency Runtime's imported `GetProcessorCount` function so the game sees a configurable thread count; the default is four, and the code reads an optional `-threads N` argument.

## Build

Open `SM-ThreadLimiter.sln` in Visual Studio and build the x64 configuration.

## Status

This is a small Windows-specific mod component, not a standalone application. It depends on the target process importing the expected Concurrency Runtime function, so behavior can vary with the game and runtime versions.
