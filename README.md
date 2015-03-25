acl
==============

####Table of Contents

1. [Overview - What is the acl module?](#overview)
2. [Module Description - What does the module do?](#module-description)
3. [Setup - The basics of getting started with acl](#setup)
    * [Beginning with acl - Installation](#beginning-with-acl)
4. [Usage - The custom type available for configuration](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
6. [Limitations - Known issues in acl](#limitations)
7. [Development - Guide for contributing to the module](#development)

##Overview

The acl module lets you use Puppet to manage Access Control Lists (ACLs) on Windows.

##Module Description

Windows uses Access Control Lists (ACLs) to store permissions information. An ACL is typically made up of a series of Access Control Entries (ACEs), representing individual permissions. The acl module adds a type and provider to let you manage all that information through Puppet.

##Setup

Install this module with the following command:


~~~
$ puppet module install [--modulepath <path>] puppetlabs/acl
~~~

The above command also includes the optional argument to specify your Puppet master's `modulepath` as the location to install the module.

###Beginning with acl

For a basic implementation of the acl module, provide a target ACL and at least one permission:


~~~
acl { 'c:/tempperms':
  permissions => [
   { identity => 'Administrator', rights => ['full'] },
   { identity => 'Users', rights => ['read','execute'] }
 ],
}
~~~

##Usage


A typical ACL is made up of access control entries (ACEs), which represent individual permissions. Each ACE comprises a defined trustee (an identity, representing a user, group, or system process), a set of rights, an inheritance and propagation strategy, and an allowed/denied status.

Windows processes ACEs in order of appearance within the ACL. It expects them to be pre-sorted by allowed/denied status in the following order:
 1. 'explicit deny'
 2. 'explicit allow'
 3. 'inherited deny'
 4. 'inherited allow'

The `acl` type does not enforce the above order, and applies the ACEs based on order of appearance in your manifest. If that differs from the ordering above, Windows generates an error message.

**Note:** You cannot specify inherited ACEs in a manifest; you can only specify whether to allow upstream inheritance to flow into the managed ACL.

###Manage a basic ACL with all parameters expressed

The fully expressed ACL in the sample below produces the same settings as the [minimal sample](beginning-with-acl) in the Setup section, without relying on defaults.

~~~
acl { 'c:/tempperms':
  target                     => 'c:/tempperms',
  purge                      => 'false',
  permissions                => [
   { identity => 'Administrator', rights => ['full'], perm_type=> 'allow', child_types => 'all', affects => 'all' },
   { identity => 'Users', rights => ['read','execute'], perm_type=> 'allow', child_types => 'all', affects => 'all' }
  ],
  owner                      => 'Administrators', #Creator_Owner specific, doesn't manage unless specified
  group                      => 'Users', #Creator_Group specific, doesn't manage unless specified
  inherit_parent_permissions => 'true',
}
~~~


###Manage multiple permissions at once

The `permissions` parameter is passed as an array, allowing it to accept multiple ACEs in the form of hashes.

~~~
acl { 'c:/tempperms':
  permissions                => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Administrator', rights => ['modify'] },
   { identity => 'Authenticated Users', rights => ['write','read','execute'] },
   { identity => 'Users', rights => ['read','execute'] }
   { identity => 'Everyone', rights => ['read'] }
  ],
  inherit_parent_permissions => 'false',
}
~~~

 * Each ACE should have a unique combination of `identity`, `perm_type`, `child_types`, and `affects` values. If you create multiple ACEs that differ only in `rights`, the module can't tell them apart and wrongly reports that the resource is out of sync.


**Wrong:**
~~~
acl { 'c:/tempperms':
  permissions => [
    { identity => 'SYSTEM', rights => ['read']},
    { identity => 'SYSTEM', rights => ['write']}
  ],
}
~~~

**Right:**

~~~
acl { 'c:/tempperms':
  permissions => [
    { identity => 'SYSTEM', rights => ['read','write']}
  ],
}
~~~

**Note:** When you run `puppet resource acl some_path`, Puppet might list some permissions with the read-only element `is_inherited => 'true'`. If you use the `resource` output in a manifest, Puppet ignores those permissions. To indicate they should be enforced on the target directly, remove the `is_inherited` property or set `is_inherited => false'`.

For more detail, see the Reference section on [`permissions`](#permissions).

###Identify users and groups with SID or FQDN

You can identify a user or group using a [security identifier](http://support.microsoft.com/kb/243330) (SID) or a fully qualified domain name (FQDN).

~~~
acl { 'c:/tempperms':
  permissions => [
   { identity => 'NT AUTHORITY\SYSTEM', rights => ['modify'] },
   { identity => 'BUILTIN\Users', rights => ['read','execute'] },
   { identity => 'S-1-5-32-544', rights => ['write','read','execute'] }
  ],
}
~~~

####Use multiple resources to manage the same target

You can manage the same target across multiple ACL resources, as long as each resource has a unique title.

**Warning:** Use this feature with care; it can get confusing quickly. Do not set `purge => 'true'` on any of the resources that apply to the same target. Doing so causes thrashing in reports, as the permissions are added and removed on every catalog application.

~~~
acl { 'c:/tempperms':
  permissions => [
   { identity => 'Administrator', rights => ['full'] }
 ],
}

acl { 'tempperms_Users':
  target      => 'c:/tempperms',
  permissions => [
   { identity => 'Users', rights => ['read','execute'] }
 ],
}
~~~

####Protect a target from inherited permissions

Removing upstream inheritance is known as "protecting" the target. When an item is protected without `purge => true`, the inherited ACEs are copied into the target as unmanaged ACEs.

~~~
acl { 'c:/tempperms':
  permissions                => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Users', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
}
~~~

####Purge unmanaged explicit permissions

You cannot purge inherited permissions; you can only purge explicit permissions. To lock down a folder to managed explicit ACEs, set `purge => true`. This only removes other explicit ACEs from the folder that are unmanaged by this resource. All inherited ACEs remain (see next example).

~~~
acl { 'c:/tempperms':
  purge       => 'true',
  permissions => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Users', rights => ['full'] }
  ],
}
~~~

####Protect a target and purge all unmanaged permissions


To fully restrict a target's permissions to the ones specified in your manifest, protect it as above and set `purge => 'true'`.

**Warning**: When removing permissions, make sure the user running Puppet always has FULL rights on the target. If Puppet loses its permission to manage a resource, you'll need to restore it manually at the node level.


~~~
acl { 'c:/tempperms':
  purge                           => 'true',
  permissions                     => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Users', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
}
~~~

####ACE mask_specific rights

If none of the standard `rights` values meets your specific needs, you can specify more granular rights by setting `rights => ['mask_specific']` and supplying a 'mask' element with an integer representing a [permissions mask](http://msdn.microsoft.com/en-us/library/aa394063(v=vs.85).aspx). You can't combine the mask with other values, such as read permissions.

**NOTE:** 'mask_specific' should ONLY be used when other rights are not specific enough. If you specify 'mask_specific' with the equivalent of 'full' rights (2032127), and Puppet finds the property to be 'full', it reports making changes to the resource even though nothing is different.

~~~
acl { 'c:/tempperms':
  purge                      => 'true',
  permissions                => [
   { identity => 'Administrators', rights => ['full'] }, #full is same as - 2032127 aka 0x1f01ff but you should use 'full'
   { identity => 'SYSTEM', rights => ['modify'] }, #modify is same as 1245631 aka 0x1301bf but you should use 'modify'
   { identity => 'Users', rights => ['mask_specific'], mask => 1180073 }, #RX WA #0x1201a9
   { identity => 'Administrator', rights => ['mask_specific'], mask => 1180032 }  #RA,S,WA,Rc #1180032  #0x120180
  ],
  inherit_parent_permissions => 'false',
}
~~~

**More about ACE masks:**

 * File/Directory Access Mask Constants: http://msdn.microsoft.com/en-us/library/aa394063(v=vs.85).aspx
 * Generic File Access Rights: http://msdn.microsoft.com/en-us/library/windows/desktop/aa364399(v=vs.85).aspx
 * Access Mask Format: http://msdn.microsoft.com/en-us/library/windows/desktop/aa374896(v=vs.85).aspx


####Explicitly deny permissions


By default, each ACE grants the described permissions to the target. However, you can reverse that by setting `perm_type => 'deny'`, which explicitly removes the described permissions. List your 'deny' ACEs first, before your 'allow' ACEs.

~~~
acl { 'c:/tempperms':
  permissions => [
   { identity => 'SYSTEM', rights => ['full'], perm_type=> 'deny', affects => 'self_only' },
   { identity => 'Administrators', rights => ['full'] }
  ],
}
~~~

####ACE inheritance

The inheritance structure of ACEs is controlled by [`child_types`](#permissions), which determine how files and sub-folders inherit each ACE.

~~~
acl { 'c:/tempperms':
  purge                      => 'true',
  permissions                => [
   { identity => 'SYSTEM', rights => ['full'], child_types => 'all' },
   { identity => 'Administrators', rights => ['full'], child_types => 'containers' },
   { identity => 'Administrator', rights => ['full'], child_types => 'objects' },
   { identity => 'Users', rights => ['full'], child_types => 'none' }
  ],
  inherit_parent_permissions => 'false',
}
~~~

####ACE propagation

ACEs have propagation rules which guide how they apply permissions to containers, objects, children, and grandchildren. Propagation is determined by [`affects`](#permissions), which can take the value of: 'all', 'self_only', 'children_only', 'direct_children_only', and 'self_and_direct_children_only'. Microsoft has a [good matrix](http://msdn.microsoft.com/en-us/library/ms229747.aspx) that outlines when and why you might use each of these values.

~~~
acl { 'c:/tempperms':
  purge                      => 'true',
  permissions                => [
   { identity => 'Administrators', rights => ['modify'], affects => 'all' },
   { identity => 'Administrators', rights => ['full'], affects => 'self_only' },
   { identity => 'Administrator', rights => ['full'], affects => 'direct_children_only' },
   { identity => 'Users', rights => ['full'], affects => 'children_only' },
   { identity => 'Authenticated Users', rights => ['read'], affects => 'self_and_direct_children_only' }
  ],
  inherit_parent_permissions => 'false',
}
~~~

####Removing ACE permissions

To remove permissions, set `purge => listed_permissions`. This removes explicit permissions from the ACL based on their `identity`, `perm_type`, `child_types` and `affects` attributes. The example below ensures that 'Administrator' and 'Authenticated Users' are not on the ACL.

~~~
#set permissions
acl { 'c:/tempperms/remove':
  purge                      => 'true',
  permissions                => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Administrator', rights => ['write'] },
   { identity => 'Users', rights => ['write','execute'] },
   { identity => 'Everyone', rights => ['execute'] },
   { identity => 'Authenticated Users', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
}

#now remove some permissions
acl { 'remove_tempperms/remove':
  target                     => 'c:/tempperms/remove',
  purge                      => 'listed_permissions',
  permissions                => [
   { identity => 'Administrator', rights => ['write'] },
   { identity => 'Authenticated Users', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
  require                    => Acl['c:/tempperms/remove'],
}
~~~

####Same identity, multiple ACEs

With Windows, you can specify the same `identity` with different inheritance and propagation. Each of the resulting items is managed as a separate ACE.

~~~
acl { 'c:/tempperms':
  purge                      => 'true',
  permissions                => [
   { identity => 'SYSTEM', rights => ['modify'], child_types => 'none' },
   { identity => 'SYSTEM', rights => ['modify'], child_types => 'containers' },
   { identity => 'SYSTEM', rights => ['modify'], child_types => 'objects' },
   { identity => 'SYSTEM', rights => ['full'], affects => 'self_only' },
   { identity => 'SYSTEM', rights => ['read','execute'], affects => 'direct_children_only' },
   { identity => 'SYSTEM', rights => ['read','execute'], child_types=>'containers', affects => 'direct_children_only' },
   { identity => 'SYSTEM', rights => ['read','execute'], child_types=>'objects', affects => 'direct_children_only' },
   { identity => 'SYSTEM', rights => ['full'], affects => 'children_only' },
   { identity => 'SYSTEM', rights => ['full'], child_types=>'containers', affects => 'children_only' },
   { identity => 'SYSTEM', rights => ['full'], child_types=>'objects', affects => 'children_only' },
   { identity => 'SYSTEM', rights => ['read'], affects => 'self_and_direct_children_only' },
   { identity => 'SYSTEM', rights => ['read'], child_types=>'containers', affects => 'self_and_direct_children_only' },
   { identity => 'SYSTEM', rights => ['read'], child_types=>'objects', affects => 'self_and_direct_children_only' }
  ],
  inherit_parent_permissions => 'false',
}
~~~


##Reference

###Define: acl

The main type of the module, responsible for all its functionality.

####Parameters


All of the below parameters are optional, unless otherwise noted.

#####`group`

Specifies whose permissions to manage. This identity is also known as a trustee or principal. If the identity doesn't exist on a node, Puppet creates it. Valid options: a string containing a valid identity (see below). Default: if left undefined, Puppet leaves the group as currently configured.

Valid identity formats:

 * User: e.g., 'Bob' or 'TheNet\Bob'
 * Group: e.g., 'Administrators' or 'BUILTIN\Administrators'
 * SID (Security ID): e.g., 'S-1-5-18'

**NOTE**: On Windows the CREATOR GROUP inherited ACE must be set for the creator's primary group for it to be set as an ACE automatically. Group is not always widely used. By default, the group also needs to be specifically set as an explicitly managed ACE. See [Microsoft's page](http://support.microsoft.com/kb/126629) for instructions on enabling CREATOR GROUP.

#####`inherit_parent_permissions`

Specifies whether to inherit permissions from parent ACLs. Valid options: 'true' and 'false'. Default: 'true'.

#####`name`

Provides a name for the ACL resource; also becomes the target, if `target` is not set. Valid options: a string. Default: the title of your declared resource.

#####`owner`

The identity that owns the ACL. If the identity doesn't exist on a node, Puppet creates it. This identity is also known as a trustee or principal. Valid options: a string containing a valid identity (see below). Default: if left undefined, Puppet leaves the owner as currently configured.

Valid identity formats:

 * User: e.g., 'Bob' or 'TheNet\Bob'
 * Group: e.g., 'Administrators' or 'BUILTIN\Administrators'
 * SID (Security ID): e.g., 'S-1-5-18'

#####`permissions`

*Required.* Specifies one or more Access Control Entries (ACEs). Valid options: an ordered array of hashes, each containing at least the `identity` and `rights` elements, and any number of additional elements from the list below.

**Elements in `permissions`**

 * `affects`: *Optional.* Determines how the downstream inheritance is propagated. Valid options: 'all', 'self_only', 'children_only', 'self_and_direct_children_only', and 'direct_children_only'. Default: 'all'.

 * `child_types`: *Optional.* Determines how an ACE is inherited downstream from the target. Valid options: 'all', 'objects', 'containers' and 'none'. Default: 'all'.


 * `identity`: *Required.* Determines whose permissions to manage. If the specified identity doesn't exist on a node, Puppet creates it. Valid options: a user (e.g., 'Bob' or 'TheNet\Bob'), group (e.g., 'Administrators' or 'BUILTIN\Administrators'), or security ID (e.g., 'S-1-5-18').


 * `mask`: *Required if `rights => 'mask_specific'` is set.* Indicates rights granted or denied to the trustee. If the `rights` element isn't set to 'mask_specific', the `mask` element has no effect. Valid options: an integer representing a [permissions mask](http://msdn.microsoft.com/en-us/library/aa394063(v=vs.85).aspx).

  If you want more granular detail about `mask` values, we've provided an [ACL Mask Rights Addition spreadsheet](https://github.com/puppetlabs/puppetlabs-acl/blob/master/tools/ACL_Access_Rights_Mask_Addition.xlsx) in the acl module's `tools` directory.

 * `perm_type`: *Optional.* Specifies whether the target should or should *not* have the described permissions. Valid options: 'allow' and 'deny'. Default: 'allow'.


 * `rights`: *Required.*: Valid options: an array containing one or more of the following values: 'full', 'modify', 'mask_specific', 'write', 'read', and 'execute'.

**NOTE:** The `type` element is deprecated and has been replaced with `perm_type`, because the word `type` will be a reserved keyword in Puppet 4.

    * 'read', 'write', and 'execute' can be used together in any combination.
    * 'modify' includes READ, WRITE, EXECUTE, and DELETE all in one.
    * 'full' indicates all rights.
    * 'full', 'modify', and 'mask_specific' values are mutually exclusive. If you use any of them, it must be the *only* `rights` value in the hash.
    * If you specify 'full' or 'modify' along with other rights, e.g., `rights => ['full','read']`, the `acl` type issues a warning and removes the other items.
    * If you specify 'mask_specific', you must also specify the `mask` element in the `permissions` hash with an integer representing a [permissions mask](http://msdn.microsoft.com/en-us/library/aa394063(v=vs.85).aspx).

#####`purge`

Specifies whether to remove any explicit permissions not specified in the `permissions` property. Valid options: 'true', 'false', and 'listed_permissions'. Default: 'false'.

To ensure that a specific set of permissions are absent from the ACL, set `purge => 'listed_permissions'`.

**Note:** This parameter only affects explicit permissions. To remove inherited permissions, use `inherit_parent_permissions => 'false'`.

**Warning:** When removing permissions, make sure the user running Puppet always has FULL rights on the target. If Puppet loses its permission to manage a resource, you'll need to restore it manually at the node level.

#####`target`

*Optional.* The location of the ACL resource. Defaults to `name` value. Valid options: a string containing an absolute path. Default: title of your declared resource.

##Limitations

 * The Windows Provider does not follow Symlinks. Please explicitly manage the permissions of the target.

 * The 8.3 short filename format used in some versions of Windows is not supported.

 * We don't recommend using the acl module with Cywin, because it can yield inconsistent results --- especially when using Cygwin SSHD with public key authentication. For example, the 'Administrator' identity might work normally on Windows 2012, but on Windows 2008 it might be translated to 'cyg_server' (or vice-versa).

 * Unicode encoding isn't supported in the `identity`, `group`, or `owner` parameters.


 * When using SIDs for identities, autorequire tries to match to users with fully qualified names (e.g., User[BUILTIN\Administrators]) in addition to SIDs (User[S-1-5-32-544]). However, it can't match against 'User[Administrators]', because that could cause issues if domain accounts and local accounts share the same name e.g., 'Domain\Bob' and 'LOCAL\Bob'.

Please log tickets and issues at our [Module Issue Tracker](https://tickets.puppetlabs.com/browse/MODULES).

##Development

Puppet Labs modules on the Puppet Forge are open projects, and community contributions are essential for keeping them great. We can’t access the huge number of platforms and myriad of hardware, software, and deployment configurations that Puppet is intended to serve.

We want to keep it as easy as possible to contribute changes so that our modules work in your environment. There are a few guidelines that we need contributors to follow so that we can have a chance of keeping on top of things.

For more information, see our [module contribution guide.](https://docs.puppetlabs.com/forge/contributing.html)

###Contributors

To see who's already involved, see the [list of contributors.](https://github.com/puppetlabs/puppetlabs-acl/graphs/contributors)
