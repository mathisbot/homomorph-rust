# Contributing

This document outlines the guidelines and steps for contributing to this repository.

## Getting Started

To get started with contributing, please follow these steps:
1. Fork the repository on GitHub
2. Open a draft PR explaining what you want to add
3. Provide a clear and descriptive title for your pull request
4. Include a detailed description of the changes you have made

## Contributing Guidelines

Before pushing, you can run `check.ps1` or `check.sh`
to launch a small local pipeline checking the state of the code,
to make sure there are no regressions,
but also that the new code respects certain standards.

To make it easier to modify the added code in the future,
take time to ensure that your code is well covered by tests.
Don't hesitate to use `tarpaulin`.

## Submitting your changes

When you are ready to submit your contribution, please follow these steps:
1. Ensure that your branch is up to date with the latest changes from the main branch
2. Push your branch to your forked repository
3. Delete the draft status from your pull request on the main repository
4. Wait for feedback and address any requested changes

## Reporting Issues

If you encounter any issues or have suggestions for improvements, please open an issue on the GitHub repository. Provide as much detail as possible.

Don't treat security issues any differently: I doubt this code will be used in production by anyone ;)
