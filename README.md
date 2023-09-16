# ArmA File Format Library
This project provides developers with libraries that enable them to read common files that are mainly used by [Bohemia Interactive][1] for their games of the ArmA series, like rapified configs (config.bin), textures (\*.paa,\*.pac), skeletal animations (\*.rtm), game file container (\*.pbo) etc.

> [!NOTE]
> This is a fork created specifically for [PboSpy](https://github.com/rvost/PboSpy). The original repository can be found [here](https://github.com/Braini01/bis-file-formats), and another currently active fork by one of the main contributors can be found [there](https://github.com/jetelain/bis-file-formats).

## The Idea, Goal and Vision
The basic idea is to create a central and public code base for those ArmA file formats, that is easy to use and integrate into a project. Ideally, this project would become the one stop shop for every developer working with those file formats. Such efforts have not had much success in the past and with this project some of the common reasons for this are tried to be avoided (see Features).

## Features

### Modularity
By providing small packages you can keep your project slick and don't need to include huge libraries with stuff you do not care about.

### Portability
The libraries are created using the [.NET Standard][2]. This makes it possible to use the libraries in most .NET applications and or libraries regardless of it being a .NET Core, .NET Framework, Mono, UWP or Xamarin application or library. With .NET Core being available on most platforms a good degree of platform-independence is achieved. You also can choose from a [lot of programming languages][3] to write a .NET application, like C#, F#, C++/CLI, VB.NET and many more.

### NuGet packages
By making all the libs available as NuGet packages, integrating a library into your project becomes a breeze.

However, it doesn't feel right to publish these packages on NuGet.org, as I'm not a major contributor. So I push them to a personal Github NuGet package registry.  If you prefer packages to source dependencies, you can find them at `https://nuget.pkg.github.com/rvost/index.json`. 

See the NuGet registry [documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry) and [this blog](https://samlearnsazure.blog/2021/08/08/consuming-a-nuget-package-from-github-packages/) post  on how to consume them.

> [!WARNING]
> Note that package identifiers start with `BIS.Formats` rather than `BIS` to avoid name clashes with (completely unrelated) packages on NuGet.org.

## Current Project State
The code you can find here is basically a little reorganized dump of some of the code that I created over the years researching those file formats. It currently basically enables you to read most files. It probably is often missing important accessors or functions that would be useful for a public API and I hope by putting this as an open source project that a lot of people will contribute to make this code base useful. So I highly encourage everyone to post some PRs to make this a great API.

_*End of original README*_

This fork is in maintenance mode and only changes required by PboSpy are made. But I'm considering backporting changes from other forks to be available in packages.

Currently, packages are being built for .NET Standard 2.0 according to the original project vision, but it is possible that migration to the .NET LTS version may occur in the future.

[1]: https://www.bistudio.com/
[2]: https://github.com/dotnet/standard
[3]: https://en.wikipedia.org/wiki/List_of_CLI_languages
