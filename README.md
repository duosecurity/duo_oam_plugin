# Deprecation Notice

This repository is deprecated by Duo Security.  The repository will remain public and visible, and integrations built using this repository’s code will continue to work.  You can also continue to fork, clone, or pull from this repository.

However, Duo will not provide any further releases or enhancements.

Duo recommends migrating your application to the Duo Universal Prompt. Refer to [our documentation](https://duo.com/docs/universal-prompt-update-guide) for more information on how to update.

For frequently asked questions about the impact of this deprecation, please see the [Repository Deprecation FAQ](https://duosecurity.github.io/faq.html)

----

[![Build Status](https://github.com/duosecurity/duo_oam_plugin/workflows/Java%20CI/badge.svg)](https://github.com/duosecurity/duo_oam_plugin/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_oam_plugin)](https://github.com/duosecurity/duo_oam_plugin/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_oam_plugin)](https://github.com/duosecurity/duo_oam_plugin/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_oam_plugin)](https://github.com/duosecurity/duo_oam_plugin/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_oam_plugin/blob/master/LICENSE)

# Overview

**duo_oam** - Duo two-factor authentication for Oracle Access Manager.

# Usage

Instructions for installing and using the plugin can be found at Duo's documentation page linked below.  A download of the plugin files can also be found on that page.

Documentation and download: <https://www.duosecurity.com/docs/oam>

# Development

If you want to build the plugin yourself, make sure you have JDK 6 (or higher) and Apache Maven installed.  Then run `mvn package` from the base directory.  This will generate a zip in the `target` directory that contains the necessary `.jar` and `.war` files.

This repository is a read-only mirror of the official plugin repository, so we cannot accept pull requests via GitHub.  Please use a GitHub issue for any requests or bugs.

# Support

Report any bugs, feature requests, etc. to us directly:
<https://github.com/duosecurity/duo_oam/issues>

Have fun!

<http://www.duosecurity.com>
