<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org).

## [v5.0.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v5.0.1) - 2024-06-27

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v5.0.0...v5.0.1)

## [v5.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v5.0.0) - 2023-04-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.1.2...v5.0.0)

### Changed

- (CONT-686) - Add Puppet 8/Drop Puppet 6 [#279](https://github.com/puppetlabs/puppetlabs-acl/pull/279) ([jordanbreen28](https://github.com/jordanbreen28))

## [v4.1.2](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.1.2) - 2023-03-21

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.1.1...v4.1.2)

### Fixed

- pdksync - (CONT-494) Pin github_changelog_generator and JSON gem versions [#270](https://github.com/puppetlabs/puppetlabs-acl/pull/270) ([david22swan](https://github.com/david22swan))

## [v4.1.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.1.1) - 2022-10-03

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.1.0...v4.1.1)

### Fixed

- Removing unsupported windows versions [#265](https://github.com/puppetlabs/puppetlabs-acl/pull/265) ([jordanbreen28](https://github.com/jordanbreen28))
- (GH-260) Update mask docs [#263](https://github.com/puppetlabs/puppetlabs-acl/pull/263) ([pmcmaw](https://github.com/pmcmaw))
- (MODULES-10908) fix noop behavior [#261](https://github.com/puppetlabs/puppetlabs-acl/pull/261) ([garrettrowell](https://github.com/garrettrowell))

## [v4.1.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.1.0) - 2022-05-23

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v4.0.0...v4.1.0)

### Added

- pdksync - (FM-8922) - Add Support for Windows 2022 [#253](https://github.com/puppetlabs/puppetlabs-acl/pull/253) ([david22swan](https://github.com/david22swan))

## [v4.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v4.0.0) - 2021-03-01

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.2.1...v4.0.0)

### Changed

- pdksync - Remove Puppet 5 from testing and bump minimal version to 6.0.0 [#229](https://github.com/puppetlabs/puppetlabs-acl/pull/229) ([carabasdaniel](https://github.com/carabasdaniel))

## [v3.2.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.2.1) - 2020-11-30

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.2.0...v3.2.1)

### Fixed

- (IAC-1089) Remove dependency on 'win32/security' gem for Puppet 7 compatibility [#208](https://github.com/puppetlabs/puppetlabs-acl/pull/208) ([sanfrancrisko](https://github.com/sanfrancrisko))

## [v3.2.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.2.0) - 2020-08-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.1.1...v3.2.0)

### Added

- pdksync - (IAC-973) - Update travis/appveyor to run on new default branch main [#199](https://github.com/puppetlabs/puppetlabs-acl/pull/199) ([david22swan](https://github.com/david22swan))

### Fixed

- (IAC-976) - Removal of inappropriate terminology [#203](https://github.com/puppetlabs/puppetlabs-acl/pull/203) ([pmcmaw](https://github.com/pmcmaw))

## [v3.1.1](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.1.1) - 2020-04-08

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.1.0...v3.1.1)

### Fixed

- [MODULES-1336] Fix noop failure reports [#188](https://github.com/puppetlabs/puppetlabs-acl/pull/188) ([carabasdaniel](https://github.com/carabasdaniel))

## [v3.1.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.1.0) - 2019-12-03

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/v3.0.0...v3.1.0)

## [v3.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/v3.0.0) - 2019-07-23

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/2.1.0...v3.0.0)

### Changed

- (MODULES-9297) Raise lower Puppet bound to 5.5.10 [#152](https://github.com/puppetlabs/puppetlabs-acl/pull/152) ([eimlav](https://github.com/eimlav))

### Added

- (MODULES-9304) Add Puppet Strings docs [#153](https://github.com/puppetlabs/puppetlabs-acl/pull/153) ([eimlav](https://github.com/eimlav))
- (WIN280) add skip() unless pattern to tests  [#145](https://github.com/puppetlabs/puppetlabs-acl/pull/145) ([ThoughtCrhyme](https://github.com/ThoughtCrhyme))

## [2.1.0](https://github.com/puppetlabs/puppetlabs-acl/tree/2.1.0) - 2018-10-11

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/2.0.1...2.1.0)

### Added

- (MODULES-6739) Add Testmode switcher [#124](https://github.com/puppetlabs/puppetlabs-acl/pull/124) ([jpogran](https://github.com/jpogran))

### Fixed

- (MODULES-5364) All version negative/prop_file fix [#110](https://github.com/puppetlabs/puppetlabs-acl/pull/110) ([Iristyle](https://github.com/Iristyle))

## [2.0.1](https://github.com/puppetlabs/puppetlabs-acl/tree/2.0.1) - 2017-08-03

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/2.0.0...2.0.1)

### Fixed

- (MODULES-5152) Fix ACE mutation on output [#105](https://github.com/puppetlabs/puppetlabs-acl/pull/105) ([Iristyle](https://github.com/Iristyle))

## [2.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/2.0.0) - 2017-05-19

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.1.2...2.0.0)

### Changed

- (MODULES-4275) Customize ACE YAML serialization [#97](https://github.com/puppetlabs/puppetlabs-acl/pull/97) ([Iristyle](https://github.com/Iristyle))

### Fixed

- Fix frozen string [#85](https://github.com/puppetlabs/puppetlabs-acl/pull/85) ([hunner](https://github.com/hunner))
- Workaround frozen strings on ruby 1.9 [#82](https://github.com/puppetlabs/puppetlabs-acl/pull/82) ([hunner](https://github.com/hunner))
- (MODULES-3632) Use json_pure always [#81](https://github.com/puppetlabs/puppetlabs-acl/pull/81) ([hunner](https://github.com/hunner))

## [1.1.2](https://github.com/puppetlabs/puppetlabs-acl/tree/1.1.2) - 2015-12-07

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.1.1...1.1.2)

## [1.1.1](https://github.com/puppetlabs/puppetlabs-acl/tree/1.1.1) - 2015-07-29

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.1.0...1.1.1)

## [1.1.0](https://github.com/puppetlabs/puppetlabs-acl/tree/1.1.0) - 2015-02-17

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.0.4...1.1.0)

## [1.0.4](https://github.com/puppetlabs/puppetlabs-acl/tree/1.0.4) - 2014-12-30

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.0.3...1.0.4)

### Added

- ACL Access Rights Mask Addition Worksheet [#44](https://github.com/puppetlabs/puppetlabs-acl/pull/44) ([ferventcoder](https://github.com/ferventcoder))

### Fixed

- (MODULES-1482) Fix Autorequires to only include resource title [#46](https://github.com/puppetlabs/puppetlabs-acl/pull/46) ([ferventcoder](https://github.com/ferventcoder))

## [1.0.3](https://github.com/puppetlabs/puppetlabs-acl/tree/1.0.3) - 2014-08-27

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.0.2...1.0.3)

### Changed

- (MODULES-1174) Puppet 3.7 compatibility [#38](https://github.com/puppetlabs/puppetlabs-acl/pull/38) ([Iristyle](https://github.com/Iristyle))

### Fixed

- install puppet when running against foss [#37](https://github.com/puppetlabs/puppetlabs-acl/pull/37) ([justinstoller](https://github.com/justinstoller))

## [1.0.2](https://github.com/puppetlabs/puppetlabs-acl/tree/1.0.2) - 2014-07-16

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.0.1...1.0.2)

## [1.0.1](https://github.com/puppetlabs/puppetlabs-acl/tree/1.0.1) - 2014-05-27

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/1.0.0...1.0.1)

## [1.0.0](https://github.com/puppetlabs/puppetlabs-acl/tree/1.0.0) - 2014-05-21

[Full Changelog](https://github.com/puppetlabs/puppetlabs-acl/compare/14896caa52cfc479e4788442fe965492e94e6917...1.0.0)
