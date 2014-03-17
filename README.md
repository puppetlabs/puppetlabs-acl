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

##Usage

At a minimum, you need to provide the target and at least one permission (access control entry or ACE). It will default the other settings to sensible defaults.

Minimally expressed sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      permissions => [
       { identity => 'Administrator', rights => ['full'] },
       { identity => 'Users', rights => ['read','execute'] }
     ],
    }


If you want you can provide a fully expressed ACL. The fully expressed acl in the sample below produces the same settings as the minimal sample above.

Fully expressed sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      target      => 'c:/tempperms',
      target_type => 'file',
      purge       => 'false',
      permissions => [
       { identity => 'Administrator', rights => ['full'], type=> 'allow', child_types => 'all', affects => 'all' },
       { identity => 'Users', rights => ['read','execute'], type=> 'allow', child_types => 'all', affects => 'all' }
      ],
      owner       => 'Administrators', #Creator_Owner specific, doesn't manage unless specified
      group       => 'Users', #Creator_Owner specific, doesn't manage unless specified
      inherit_parent_permissions => 'true',
    }


Adding in multiple users is done by just adding users to the list of permissions. You can also see that you can specify Domain qualified users and SIDs if you need to. SIDs reference - http://support.microsoft.com/kb/243330

Multi-user sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      purge       => 'true',
      permissions => [
       { identity => 'NT AUTHORITY\SYSTEM', rights => ['modify'] },
       { identity => 'BUILTIN\Users', rights => ['read','execute'] },
       { identity => 'S-1-5-32-544', rights => ['write','read','execute'] }
      ],
      inherit_parent_permissions => 'false',
    }


You can manage the same target across multiple acl resources with some caveats. The title of the resource needs to be unique. It is suggested that you only do this when you would need to (can get confusing). You should not set `purge => 'true'` on any of the resources that apply to the same target or you will see thrashing in reports as the permissions will be added and removed every catalog application. Use this feature with care.

Manage same ACL resource multiple acls sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      permissions => [
       { identity => 'Administrator', rights => ['full'] }
     ],
    }

    acl { 'tempperms_Users':
      ensure      => present,,
      target      => 'c:/tempperms',
      permissions => [
       { identity => 'Users', rights => ['read','execute'] }
     ],
    }


Removing upstream inheritance is known as "protecting" the target. When an item is "protected" without `purge => true`, the inherited ACEs will be copied into the target as unmanaged ACEs.

Protected ACL sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Users', rights => ['full'] }
      ],
      inherit_parent_permissions => 'false',
    }


To lock down a folder to managed explicit ACEs, you want to set `purge => true`. This will only remove other explicit ACEs from the folder that are unmanaged by this resource. All inherited ACEs will remain (see next example).

Purge sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Users', rights => ['full'] }
      ],
      inherit_parent_permissions => 'false',
    }


To lock down a folder to only the permissions specified in the manifest resource, you want to protect the folder and set `purge => 'true'`. This ensure that the only permissions on the folder are the ones that you have set explicitly in the manifest.

Protected with purge sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Users', rights => ['full'] }
      ],
      inherit_parent_permissions => 'false',
    }


ACE rights can be: 'full', 'modify', 'write', 'read', 'execute', and/or 'mask_specific'. 'full', 'modify', and 'mask_specific' are mutually exclusive, that is they should be the only thing specified in rights if they are applicable. 'full' indicates all rights, so it is cumulative. 'modify' indicates 'write', 'read', 'execute' and DELETE so it is also cumulative. If you specify 'full' or 'modify' as part of a set of rights with other rights e.g. `rights => ['full','read']`, the `acl` type will issue a warning and remove the other items. You can specify any combination of 'write', 'read', and 'execute'. More on 'mask_specific' in the next section.


Rights sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      permissions => [
       { identity => 'Administrators', rights => ['full'] },
       { identity => 'Administrator', rights => ['modify'] },
       { identity => 'Authenticated Users', rights => ['write','read','execute'] },
       { identity => 'Users', rights => ['read','execute'] }
       { identity => 'Everyone', rights => ['read'] }
      ],
      inherit_parent_permissions => 'false',
    }


ACE `rights => ['mask_specific']` indicates that rights are passed as part of a mask, so the mask is all that will be evaluated. When you specify 'mask_specific' you must also specify `mask` with an integer (passed as a string) that represents the permissions mask. Because the mask is all that is evaluated, it is important that you don't try to combine something like read permissions and then the mask e.g. `rights => ['read','mask_specific']` (invalid scenario). In fact, the `ACL` provider will error if you attempt to do this because it could set the system in an unusable state due to a misunderstanding of how this particular feature works.

Mask specific sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      purge       => 'true',
      permissions => [
       { identity => 'Administrators', rights => ['full'] }, #full is same as - 2032127 aka 0x1f01ff but you should use 'full'
       { identity => 'SYSTEM', rights => ['modify'] }, #modify is same as 1245631 aka 0x1301bf but you should use 'modify'
       { identity => 'Users', rights => ['mask_specific'], mask => '1180073' }, #RX WA #0x1201a9
       { identity => 'Administrator', rights => ['mask_specific'], mask => '1180032' }  #RA,WA,Rc #1180032  #0x120180
      ],
      inherit_parent_permissions => 'false',
    }


ACEs can be of type 'allow' (default) or 'deny'. Deny ACEs should be listed first before allow ACEs.

Deny ACE sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      permissions => [
       { identity => 'SYSTEM', rights => ['full'], type=> 'deny', affects => 'self_only' },
       { identity => 'Administrators', rights => ['full'] }
      ],
    }


ACEs have inheritance structures as well aka "child_types": 'all' (default), 'none', 'containers', and 'objects'. This controls how sub-folders and files will inherit each particular ACE.

ACE inheritance "child_types" sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
      purge       => 'true',
      permissions => [
       { identity => 'SYSTEM', rights => ['full'], child_types => 'all' },
       { identity => 'Administrators', rights => ['full'], child_types => 'containers' },
       { identity => 'Administrator', rights => ['full'], child_types => 'objects' },
       { identity => 'Users', rights => ['full'], child_types => 'none' }
      ],
      inherit_parent_permissions => 'false',
    }


ACEs have propagation rules, a nice way of saying "how" they apply permissions to containers, objects, children and grandchildren. Propagation aka "affects" can take the value of: 'all' (default), 'self_only', 'children_only', 'direct_children_only', and 'self_and_direct_children_only'.

ACE propagation "affects" sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
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


An interesting note with Windows, you can specify the same identity with different inheritance and propagation and each of those items will actually be managed as separate ACEs.

Same user multiple ACEs sample usage:

    acl { 'c:/tempperms':
      ensure      => present,
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
 * When using SIDs for identities, autorequire will attempt to match to users with fully qualified names (`User[BUILTIN\Administrators]`) in addition to SIDs (`User[S-1-5-32-544]`). The limitation is that it won't match against `User[Administrators]` as that could cause issues if attempting to match domain accounts versus local accounts with the same name e.g. `Domain\Bob` vs `LOCAL\Bob`.

##License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)
