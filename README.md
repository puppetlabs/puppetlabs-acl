ACL (Access Control List)
==============

##Overview

This module adds a type and windows provider for managing permissions. The `acl` type is typically used when you need more complex management of permissions e.g. Windows.

##Module Description

This module provides a type and provider for managing permissions. Currently, only Windows is supported.

ACLs typically contain access control entries (ACEs) that define a trustee (identity) with a set of rights, whether the type is allow or deny, and how inheritance and propagation of those ACEs are applied to the resource target and child types under it. The order that ACEs are listed in is important on Windows as it determines what is applied first.

Order of ACE application on Windows is explicit deny, explicit allow, inherited deny, then inherited allow. You cannot specify inherited ACEs in a manifest, only whether to allow upstream inheritance to flow into the managed target location (known as security descriptor). Please ensure your modeled resources follow this order or Windows will complain. NOTE: `acl` type does not enforce or complain about ACE order.

##Setup

###Beginning with ACL

The best way to install this module is with the `puppet module` subcommand.  On your puppet master or local puppet install, execute the following command, optionally specifying your puppet master's `modulepath` in which to install the module:

    $ puppet module install [--modulepath <path>] puppetlabs/acl

See the section [Installing Modules](http://docs.puppetlabs.com/puppet/2.7/reference/modules_installing.html) for more information.

##ACL Type

    acl { 'name':
      target => 'absolute/path',
      target_type => '<file>',
      purge => '<true| false | listed_permissions>',
      permissions => [
        { identity => '<identity>',
          rights => [<rights>],
          type => '<type>',
          affects => '<affects>',
          child_types => '<child_types>'
        }
        ],
      owner => '<owner>',
      group => '<group>',
      inherit_parent_permissions => '<true | false>',
    }

###Parameters
 * **name** - The name of the acl resource. Used for uniqueness. Will set the target to this value if target is unset.

 * **target** - The location the acl resource is pointing to. In the first release of ACL, this will be a file system location. The default is the name.

 * **target_type** - The type of target for the Acl resource. In the first release of ACL, only `'file'` is allowed. Defaults to `'file'`. Valid values are `file`.

 * **purge** - Purge specifies whether to remove other explicit permissions if not specified in the permissions set. This doesn't do anything with permissions inherited from parents (to remove those you should combine `purge => 'false', inherit_parent_permissions => 'false'`. This also allows you to ensure the permissions listed are not on the ACL with `purge => 'listed_permissions'`. The default is `'false'`. Valid values are `true`, `false`, `listed_permissions`.

###Properties

 * **inherit_parent_permissions** - Inherit Parent Permissions specifies whether to inherit permissions from parent ACLs or not. The default is `true`. Valid values are `true`, `false`. Requires feature `can_inherit_parent_permissions`.

 * **owner** - The owner identity is also known as a trustee or principal that is said to own the particular acl/security descriptor. This can be in the form of:
   1. User - e.g. `'Bob'` or `'TheNet\Bob'`
   1. Group e.g. `'Administrators'` or `'BUILTIN\Administrators'`
   1. SID (Security ID) e.g. `'S-1-5-18'`.

  Defaults to not specified on Windows. This allows owner to stay set to whatever it is currently
  set to (owner can vary depending on the original CREATOR OWNER). The trustee must exist on the system and will auto-require on user and group resources.

 * **group** - The group identity is also known as a trustee or principal that is said to have access to the particular acl/security descriptor. This can be in the form of:
   1. User - e.g. `'Bob'` or `'TheNet\Bob'`
   1. Group e.g. `'Administrators'` or `'BUILTIN\Administrators'`
   1. SID (Security ID) e.g. `'S-1-5-18'`.

  Defaults to not specified on Windows. This allows group to stay set to whatever it is currently set to (group can vary depending on the original CREATOR GROUP). The trustee must exist on the system and will auto-require on user and group resources.

  **NOTE**: On Windows the CREATOR GROUP inherited ACE must be set for the creator's primary group to be set as an ACE automatically. Group is not always widely used. By default the group will also need to be specifically set as an explicit managed ACE. For more information see http://support.microsoft.com/kb/126629

 * **permissions** - Permissions is an array containing Access Control Entries (ACEs). Certain Operating Systems require these ACEs to be in explicit order (Windows). Every element in the array is a hash that will at the very least need `identity` and `rights` e.g `{ identity => 'Administrators', rights => ['full'] }` and at the very most can include `type`, `child_types`, `affects`, and `mask` (mask should only be specified with `rights => ['mask_specific']`)  e.g. `{ identity => 'Administrators', rights => ['full'], type=> 'allow', child_types => 'all', affects => 'all' }`.

  * `identity` is a group, user or ID (SID on Windows). This can be in the form of:
    1. User - e.g. `'Bob'` or `'TheNet\Bob'`
    1. Group e.g. `'Administrators'` or `'BUILTIN\Administrators'`
    1. SID (Security ID) e.g. `'S-1-5-18'`.

    The `identity` must exist on the system and will auto-require on user and group resources.

  * `rights` is an array that contains `'full'`, `'modify'`, `'mask_specific'` or some combination of `'write'`, `'read'`, and `'execute'`. If you specify `'mask_specific'` you must also specify `mask` with an integer (passed as a string) that represents the permissions mask.

  * `type` is represented as `'allow'` **(default)** or `'deny'`.

  * `child_types` determines how an ACE is inherited downstream from the target. Valid values are `'all'` **(default)**, `'objects'`, `'containers'` or `'none'`.

  * `affects` determines how the downstream inheritance is propagated. Valid values are `'all'` **(default)**, `'self_only'`, `'children_only'`, `'self_and_direct_children_only'` or `'direct_children_only'`.

  Each permission (ACE) is determined to be unique based on `identity`, `type`, `child_types`, and `affects`. While you can technically create more than one ACE that differs from other ACEs only in rights, acl module is not able to tell the difference between those so it will appear that the resource is out of sync every run when it is not.

  While you will see `is_inherited => 'true'` when running `puppet resource acl some_path`, puppet will not be able to manage the inherited permissions so those will need to be removed if using that to build a manifest.

##Usage

###Minimal
At a minimum, you need to provide the target and at least one permission (access control entry or ACE). It will default the other settings to sensible defaults.

Minimally expressed sample usage:

    acl { 'c:/tempperms':
      permissions => [
       { identity => 'Administrator', rights => ['full'] },
       { identity => 'Users', rights => ['read','execute'] }
     ],
    }

###Full
If you want you can provide a fully expressed ACL. The fully expressed acl in the sample below produces the same settings as the minimal sample above.

Fully expressed sample usage:

    acl { 'c:/tempperms':
      target      => 'c:/tempperms',
      target_type => 'file',
      purge       => 'false',
      permissions => [
       { identity => 'Administrator', rights => ['full'], type=> 'allow', child_types => 'all', affects => 'all' },
       { identity => 'Users', rights => ['read','execute'], type=> 'allow', child_types => 'all', affects => 'all' }
      ],
      owner       => 'Administrators', #Creator_Owner specific, doesn't manage unless specified
      group       => 'Users', #Creator_Group specific, doesn't manage unless specified
      inherit_parent_permissions => 'true',
    }

###SID/FQDN
Users can be specified with SIDs (Security Identifiers) or as fully qualified domain names (FQDN). SIDs reference - http://support.microsoft.com/kb/243330

SID/FQDN User sample usage:

    acl { 'c:/tempperms':
      permissions => [
       { identity => 'NT AUTHORITY\SYSTEM', rights => ['modify'] },
       { identity => 'BUILTIN\Users', rights => ['read','execute'] },
       { identity => 'S-1-5-32-544', rights => ['write','read','execute'] }
      ],
    }

###Same Target Multiple Resources
You can manage the same target across multiple acl resources with some caveats. The title of the resource needs to be unique. It is suggested that you only do this when you would need to (can get confusing). You should not set `purge => 'true'` on any of the resources that apply to the same target or you will see thrashing in reports as the permissions will be added and removed every catalog application. Use this feature with care.

Manage same ACL resource multiple acls sample usage:

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

###Protect
Removing upstream inheritance is known as "protecting" the target. When an item is "protected" without `purge => true`, the inherited ACEs will be copied into the target as unmanaged ACEs.

Protected ACL sample usage:

    acl { 'c:/tempperms':
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Users', rights => ['full'] }
      ],
      inherit_parent_permissions => 'false',
    }

###Purge
To lock down a folder to managed explicit ACEs, you want to set `purge => true`. This will only remove other explicit ACEs from the folder that are unmanaged by this resource. All inherited ACEs will remain (see next example).

Purge sample usage:

    acl { 'c:/tempperms':
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Users', rights => ['full'] }
      ],
    }

###Protect with Purge
To lock down a folder to only the permissions specified in the manifest resource, you want to protect the folder and set `purge => 'true'`. This ensure that the only permissions on the folder are the ones that you have set explicitly in the manifest.

**Warning**: While managing ACLs you could lock the user running Puppet completely out of managing resources. Extreme care should be used when using `purge => true` with `inherit_parent_permissions => false` on the `acl`. If this is done and locks Puppet out of managing the resource, manual intervention on affected nodes will be required.

Protected with purge sample usage:

    acl { 'c:/tempperms':
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Users', rights => ['full'] }
      ],
      inherit_parent_permissions => 'false',
    }

###ACE Rights
ACE rights can be: 'full', 'modify', 'write', 'read', 'execute', and/or 'mask_specific'. 'full', 'modify', and 'mask_specific' are mutually exclusive, that is they should be the only thing specified in rights if they are applicable. 'full' indicates all rights, so it is cumulative. 'modify' indicates 'write', 'read', 'execute' and DELETE so it is also cumulative. If you specify 'full' or 'modify' as part of a set of rights with other rights e.g. `rights => ['full','read']`, the `acl` type will issue a warning and remove the other items. You can specify any combination of 'write', 'read', and 'execute'. More on 'mask_specific' in the next section.


Rights sample usage:

    acl { 'c:/tempperms':
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Administrator', rights => ['modify'] },
       { identity => 'Authenticated Users', rights => ['write','read','execute'] },
       { identity => 'Users', rights => ['read','execute'] }
       { identity => 'Everyone', rights => ['read'] }
      ],
      inherit_parent_permissions => 'false',
    }

###ACE Mask Specific Rights
ACE `rights => ['mask_specific']` indicates that rights are passed as part of a mask, so the mask is all that will be evaluated. When you specify 'mask_specific' you must also specify `mask` with an integer (passed as a string) that represents the permissions mask. Because the mask is all that is evaluated, it is important that you don't try to combine something like read permissions and then the mask e.g. `rights => ['read','mask_specific']` (invalid scenario). In fact, the `ACL` provider will error if you attempt to do this because it could set the system in an unusable state due to a misunderstanding of how this particular feature works.

**NOTE:** Mask specific should ONLY be used when other rights are not specific enough. If you specify mask specific with the equivalent of 'full' rights (2032127), and it finds the property to be 'full', it will report making changes to the resource even though nothing is different.

Mask specific sample usage:

    acl { 'c:/tempperms':
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['full'] }, #full is same as - 2032127 aka 0x1f01ff but you should use 'full'
       { identity => 'SYSTEM', rights => ['modify'] }, #modify is same as 1245631 aka 0x1301bf but you should use 'modify'
       { identity => 'Users', rights => ['mask_specific'], mask => '1180073' }, #RX WA #0x1201a9
       { identity => 'Administrator', rights => ['mask_specific'], mask => '1180032' }  #RA,S,WA,Rc #1180032  #0x120180
      ],
      inherit_parent_permissions => 'false',
    }


References

 * File/Directory Access Mask Constants - http://msdn.microsoft.com/en-us/library/aa394063(v=vs.85).aspx
 * File Generic Access Rights - http://msdn.microsoft.com/en-us/library/windows/desktop/aa364399(v=vs.85).aspx
 * Access Mask Format - http://msdn.microsoft.com/en-us/library/windows/desktop/aa374896(v=vs.85).aspx


###ACE Type
ACEs can be of type 'allow' (default) or 'deny'. Deny ACEs should be listed first before allow ACEs.

Deny ACE sample usage:

    acl { 'c:/tempperms':
      permissions => [
       { identity => 'SYSTEM', rights => ['full'], type=> 'deny', affects => 'self_only' },
       { identity => 'Administrators', rights => ['full'] }
      ],
    }

###ACE Child Types (Inheritance)
ACEs have inheritance structures as well aka "child_types": 'all' (default), 'none', 'containers', and 'objects'. This controls how sub-folders and files will inherit each particular ACE.

ACE inheritance "child_types" sample usage:

    acl { 'c:/tempperms':
      purge       => 'true',
      permissions => [
       { identity => 'SYSTEM', rights => ['full'], child_types => 'all' },
       { identity => 'Administrators', rights => ['full'], child_types => 'containers' },
       { identity => 'Administrator', rights => ['full'], child_types => 'objects' },
       { identity => 'Users', rights => ['full'], child_types => 'none' }
      ],
      inherit_parent_permissions => 'false',
    }

###ACE Affects (Propagation)
ACEs have propagation rules, a nice way of saying "how" they apply permissions to containers, objects, children and grandchildren. Propagation aka "affects" can take the value of: 'all' (default), 'self_only', 'children_only', 'direct_children_only', and 'self_and_direct_children_only'.

ACE propagation "affects" sample usage:

    acl { 'c:/tempperms':
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['modify'], affects => 'all' },
       { identity => 'Administrators', rights => ['full'], affects => 'self_only' },
       { identity => 'Administrator', rights => ['full'], affects => 'direct_children_only' },
       { identity => 'Users', rights => ['full'], affects => 'children_only' },
       { identity => 'Authenticated Users', rights => ['read'], affects => 'self_and_direct_children_only' }
      ],
      inherit_parent_permissions => 'false',
    }

###ACE Purge => Listed Permissions (Removing Permissions)
Removing permissions is done by using `purge => listed_permissions`. This will remove explicit permissions from the ACL. When the example below is done, it will ensure that `Administrator` and `Authenticated Users` are not on the ACL. This comparison is done based on `identity`, `type`, `child_types` and `affects`.

Removing permissions sample usage:

    #set permissions
    acl { 'c:/tempperms/remove':
      purge       => 'true',
      permissions => [
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
      target      => 'c:/tempperms/remove',
      purge       => 'listed_permissions',
      permissions => [
       { identity => 'Administrator', rights => ['write'] },
       { identity => 'Authenticated Users', rights => ['full'] }
      ],
      inherit_parent_permissions => 'false',
      require     => Acl['c:/tempperms/remove'],
    }

**Note:** possibly in a second release we could add the ability to target by identity only to ensure identity is not available.

###Same Identity Multiple ACEs
An interesting note with Windows, you can specify the same identity with different inheritance and propagation and each of those items will actually be managed as separate ACEs.

Same user multiple ACEs sample usage:

    acl { 'c:/tempperms':
      purge       => 'true',
      permissions => [
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

##Limitations

 * The Windows Provider in the first release (at least) will not handle permissions with Symlinks. Please explicitly manage the permissions of the target.
 * Each permission (ACE) is determined to be unique based on identity, type, child_types, and affects. While you can technically create more than one ACE that differs from other ACEs only in rights, acl module is not able to tell the difference between those so it will appear that the resource is out of sync every run when it is not. The following is an example of incorrect usage:

````
    acl { 'c:/tempperms':
      permissions => [
       { identity => 'SYSTEM', rights => ['full']},
       { identity => 'SYSTEM', rights => ['read']}
     ],
    }
````

 * Windows 8.3 short name format for files/directories is not supported.
 * Using Cygwin to run puppet with ACLs could result in undesirable behavior (on Windows 2008 "Administrator" identity might be translated to "cyg_server", but may behave fine on other systems like Windows 2012). We wouldn't recommend using Cygwin to run Puppet with ACL manifests due to this and other possible edge cases.
 * Unicode for identities, group, and owner may not work appropriately or at all in the first release.
 * When using SIDs for identities, autorequire will attempt to match to users with fully qualified names (`User[BUILTIN\Administrators]`) in addition to SIDs (`User[S-1-5-32-544]`). The limitation is that it won't match against `User[Administrators]` as that could cause issues if attempting to match domain accounts versus local accounts with the same name e.g. `Domain\Bob` vs `LOCAL\Bob`.

##License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)
