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
