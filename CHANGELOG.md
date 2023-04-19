# Change log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org).

## [v5.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v5.0.0) (2023-04-19)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.1.2...v5.0.0)

### Changed

- \(CONT-686\) - Add Puppet 8/Drop Puppet 6 [\#279](https://github.com/puppetlabs/puppetlabs-acl/pull/279) ([jordanbreen28](https://github.com/jordanbreen28))

## [v4.1.2](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.1.2) (2023-03-21)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.1.1...v4.1.2)

### Fixed

- pdksync - \(CONT-494\) Pin github\_changelog\_generator and JSON gem versions [\#270](https://github.com/puppetlabs/puppetlabs-acl/pull/270) ([david22swan](https://github.com/david22swan))

## [v4.1.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.1.1) (2022-10-03)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.1.0...v4.1.1)

### Fixed

- Removing unsupported windows versions [\#265](https://github.com/puppetlabs/puppetlabs-acl/pull/265) ([jordanbreen28](https://github.com/jordanbreen28))
- \(GH-260\) Update mask docs [\#263](https://github.com/puppetlabs/puppetlabs-acl/pull/263) ([pmcmaw](https://github.com/pmcmaw))
- \(MODULES-10908\) fix noop behavior [\#261](https://github.com/puppetlabs/puppetlabs-acl/pull/261) ([garrettrowell](https://github.com/garrettrowell))
- \(IAC-976\) - Removal of inappropriate terminology [\#203](https://github.com/puppetlabs/puppetlabs-acl/pull/203) ([pmcmaw](https://github.com/pmcmaw))

## [v4.1.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.1.0) (2022-05-23)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.0.0...v4.1.0)

### Added

- pdksync - \(FM-8922\) - Add Support for Windows 2022 [\#253](https://github.com/puppetlabs/puppetlabs-acl/pull/253) ([david22swan](https://github.com/david22swan))

## [v4.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.0.0) (2021-03-01)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.2.1...v4.0.0)

### Changed

- pdksync - Remove Puppet 5 from testing and bump minimal version to 6.0.0 [\#229](https://github.com/puppetlabs/puppetlabs-acl/pull/229) ([carabasdaniel](https://github.com/carabasdaniel))

## [v3.2.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.2.1) (2020-11-30)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.2.0...v3.2.1)

### Fixed

- \(IAC-1089\) Remove dependency on 'win32/security' gem for Puppet 7 compatibility [\#208](https://github.com/puppetlabs/puppetlabs-acl/pull/208) ([sanfrancrisko](https://github.com/sanfrancrisko))

## [v3.2.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.2.0) (2020-08-18)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.1.1...v3.2.0)

### Added

- pdksync - \(IAC-973\) - Update travis/appveyor to run on new default branch main [\#199](https://github.com/puppetlabs/puppetlabs-acl/pull/199) ([david22swan](https://github.com/david22swan))

## [v3.1.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.1.1) (2020-04-08)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.1.0...v3.1.1)

### Fixed

- \[MODULES-1336\] Fix noop failure reports [\#188](https://github.com/puppetlabs/puppetlabs-acl/pull/188) ([carabasdaniel](https://github.com/carabasdaniel))

## [v3.1.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.1.0) (2019-12-03)

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.0.0...v3.1.0)

## v3.0.0
  
### Summary

Major release which removes support for older versions of Puppet-Agent. Also adds support for Windows Server 2019

#### Features

- Add support for Windows Server 2019 ([FM-7693](https://tickets.puppetlabs.com/browse/FM-7693))
- Add Puppet Strings docs ([MODULES-9304](https://tickets.puppetlabs.com/browse/MODULES-9304))

#### Bug Fixes

-  Update acceptance tests to improve the quality and efficiency ([MODULES-9294](https://tickets.puppetlabs.com/browse/MODULES-9294))

#### Changed

- Raise lower Puppet bound to 5.5.10 ([MODULES-9297](https://tickets.puppetlabs.com/browse/MODULES-9297))

## 2018-10-10 - Supported Release 2.1.0

### Summary

Feature release including support for Windows Server 2016 and Puppet 6

#### Features

- Add support for Windows Server 2016
- Convert module for PDK ([MODULES-6459](https://tickets.puppetlabs.com/browse/MODULES-6459))
- Add support for Puppet 6 ([MODULES-7832](https://tickets.puppetlabs.com/browse/MODULES-7832))

#### Bug Fixes

- Update tests for Unicode on Windows
- Convert acceptance tests to rspec format ([MODULES-5978](https://tickets.puppetlabs.com/browse/MODULES-5978))
- Update module to conform with rubocop ([MODULES-5899](https://tickets.puppetlabs.com/browse/MODULES-5899))
- Add support for Beaker Testmode Switcher  ([MODULES-6739](https://tickets.puppetlabs.com/browse/MODULES-6739))

## 2017-07-31 - Supported Release 2.0.1

### Summary

Minor bugfix release

#### Bug Fixes

- Fixed issue with using ALL APPLICATION PACKAGES or ALL RESTRICTED APPLICATION PACKAGES accounts as the identity in a manifest ([MODULES-5152](https://tickets.puppetlabs.com/browse/MODULES-5227)).

## 2017-05-19 - Supported Release 2.0.0

### Summary

Major release which removes support for older versions of Puppet-Agent.  Also adds support of newer PE versions and fix for a future Puppet Agent release.

#### Features

- Added compatibility for Windows 10.
- Updated module with Puppet standard module development tools.

#### Bug Fixes

- Removed Windows 2003 as a supported Operating System.
- Fixed minor issues in testing due to changes in Gem file dependencies.
- Added support for localization.
- Updated puppet version compatibility for modern Puppet agents ([MODULES-4838](https://tickets.puppetlabs.com/browse/MODULES-4838)).
- Fixed issue ACL YAML serialization in Ruby 2.3.x ([MODULES-4275](https://tickets.puppetlabs.com/browse/MODULES-4275)).

## 2015-12-08 - Supported Release 1.1.2

### Summary

Small release for support of newer PE versions.

## 2015-07-28 - Supported Release 1.1.1

### Summary

Add Puppet 4 and PE 2015.2.0 to metadata

#### Features
- README updates
- Acceptance test fixes
- Gemfile changes

## 2015-02-17 - Supported Release 1.1.0

### Summary

Deprecates `type` in permissions array has been renamed to `perm_type`

#### Features

- Permissions parameter now takes array of hashes with `perm_type` instead of Puppet 4.0 protected word `type`

## 2014-12-30 - Supported Release 1.0.4

### Summary

Bug fixes and typo in metadata summary

## 2014-08-25 - Supported Release 1.0.3

### Summary

This release enables compatibility with x64-native ruby and puppet 3.7

## 2014-07-15 - Supported Release 1.0.2

### Summary

This release merely updates metadata.json so the module can be uninstalled and
upgraded via the puppet module command.

## 2014-03-04 - Supported Release 1.0.1

### Summary

Add metadata compatibility for PE 3.2.

## 2014-03-04 - Supported Release 1.0.0

### Summary

This is the initial supported release of the ACL module.


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
