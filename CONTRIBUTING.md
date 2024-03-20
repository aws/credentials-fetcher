# Contributing to the credentials-fetcher

Contributions to the Credentials Fetcher should be made via GitHub [pull
requests](https://github.com/aws/credentials-fetcher/pulls) and discussed using
GitHub [issues](https://github.com/aws/credentials-fetcher/issues).

### Before you start

If you would like to make a significant change, it's a good idea to first open
an issue to discuss it.

### Submit Pull Requests

We are always happy to receive code and documentation contributions to the credentials-fetcher Please be aware of the following notes prior to opening a pull request:

Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.
4. You have tested your change and added tests where appropriate. Wherever possible, pull requests should contain tests as appropriate. Bugfixes should contain tests that exercise the corrected behavior (i.e., the test should fail without the bugfix and pass with it), and new features should be accompanied by tests exercising the feature.

GitHub provides additional documentation on [Creating a Pull Request](https://help.github.com/articles/creating-a-pull-request/).

Please remember to:
* Use commit messages (and PR titles) that follow the guidelines under [Commit Your Change](#commit-your-change).
* Send us a pull request, answering any default questions in the pull request interface.
* Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

### Commit Your Change

We use commit messages to update the project version number and generate changelog entries, so it's important for them to follow the right format. Valid commit messages adhere to the [conventional commit][conventional-commit] standard and include a prefix, separated from the rest of the message by a colon and a space. Here are a few examples:

```
feature: add new field for recommendation source
fix: fix the input validation for the gRPC contract
documentation: update contributing documentation
```

Example supported prefixes are listed in the table below.

| Prefix          | Use for...                                                                                     |
|----------------:|:-----------------------------------------------------------------------------------------------|
| `feature`       | Adding a new feature.                                                                          |
| `fix`           | Bug fixes.                                                                                     |
| `refactor`      | A code refactor.                                                                                   |
| `change`        | Any other code change.                                                                         |
| `documentation` | Documentation changes.                                                                         |
| `test`          | Test changes.                                                                         |

Some of the prefixes allow abbreviation ; e.g. `feat` and `docs` are both valid. If you omit a prefix, the commit will be treated as a `change`.

For the rest of the message, use imperative style and keep things concise but informative. See [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/) for guidance.

## Licensing

The Credentials Fetcher is released under an [Apache
2.0](http://aws.amazon.com/apache-2-0/) license. Any code you submit will be
released under that license.

For significant changes, we may ask you to sign a [Contributor License
Agreement](http://en.wikipedia.org/wiki/Contributor_License_Agreement).

## Amazon Open Source Code of Conduct

This code of conduct provides guidance on participation in Amazon-managed open source communities, and outlines the process for reporting unacceptable behavior. As an organization and community, we are committed to providing an inclusive environment for everyone. Anyone violating this code of conduct may be removed and banned from the community.

**Our open source communities endeavor to:**
* Use welcoming and inclusive language;
* Be respectful of differing viewpoints at all times;
* Accept constructive criticism and work together toward decisions;
* Focus on what is best for the community and users.

**Our Responsibility.** As contributors, members, or bystanders we each individually have the responsibility to behave professionally and respectfully at all times. Disrespectful and unacceptable behaviors include, but are not limited to:
The use of violent threats, abusive, discriminatory, or derogatory language;
* Offensive comments related to gender, gender identity and expression, sexual orientation, disability, mental illness, race, political or religious affiliation;
* Posting of sexually explicit or violent content;
* The use of sexualized language and unwelcome sexual attention or advances;
* Public or private [harassment](http://todogroup.org/opencodeofconduct/#definitions) of any kind;
* Publishing private information, such as physical or electronic address, without permission;
* Other conduct which could reasonably be considered inappropriate in a professional setting;
* Advocating for or encouraging any of the above behaviors.

**Enforcement and Reporting Code of Conduct Issues.**
Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting opensource-codeofconduct@amazon.com. All complaints will be reviewed and investigated and will result in a response that is deemed necessary and appropriate to the circumstances.

**Attribution.** _This code of conduct is based on the [template](http://todogroup.org/opencodeofconduct) established by the [TODO Group](http://todogroup.org/) and the Scope section from the [Contributor Covenant version 1.4](http://contributor-covenant.org/version/1/4/)._
