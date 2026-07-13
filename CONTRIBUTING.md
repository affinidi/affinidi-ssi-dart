# Contributing

When contributing to this repository, please first discuss the change you wish to make by creating a new [GitHub issue](https://github.com/affinidi/affinidi-ssi-dart/issues/new).

## Contribution Workflow

### Review and approval

All pull requests require approval from **two independent reviewers** who are members of the maintainer team. The author of a pull request never counts as a reviewer of their own change, regardless of which account an approval is issued from. A pull request is merged only after both independent approvals are in place and all pipeline checks have passed.

### Affinidi employees

Affinidi employees contributing to Affinidi-owned repositories must do so using their **corporate GitHub account** (a member of the `affinidi` GitHub organization, associated with their `@affinidi.com` email address). This applies to authoring commits, opening pull requests, reviewing, and approving.

Pull requests opened by employees from personal accounts will not be reviewed; they should be closed and resubmitted from the corporate account.

If you are asked to review a pull request and the author's account is not a member of the `affinidi` organization, verify the author's identity before beginning your review.

### External contributors

Community contributions are welcome. Please fork the repository and open a pull request from your fork.

All commits must be signed off in accordance with the [Developer Certificate of Origin](https://developercertificate.org/). Add a sign-off to each commit with:

```
git commit -s
```

This appends a `Signed-off-by: Your Name <your@email.com>` line to the commit message, certifying that you have the right to submit the contribution under the project's license. Pull requests with unsigned commits will fail the DCO check and cannot be merged.

## Development Requirements

### Code quality expectations

1. Ensure the pipeline checks are finished successfully.
2. Ensure the pull request doesn't contain redundant comments, console.log, etc.
3. Ensure your code is covered with unit and integration tests (no mocks/stubs in integration tests).
4. Avoid adding comments to explain what code does, code should be self-explanatory and clean.
5. Avoid using variable names like `i` or abbreviations - names should be simple and unambiguous.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Avoiding obvious comments about things like code styling and indentation.
  If you see yourself wanting to do that more than once - open an issue with a repo to update the ESLint/Prettier rules to address this concern once and for all. **Code reviews should be about logic, not indenting or adding more newlines**

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting
