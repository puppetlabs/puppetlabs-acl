# The baseline for module testing used by Puppet Labs is that each manifest
# should have a corresponding test manifest that declares that class or defined
# type.
#
# Tests are then run by using puppet apply --noop (to check for compilation errors
# and view a log of events) or by fully applying the test in a virtual environment
# (to compare the resulting system state to the desired state).
#
# Learn more about module testing here: http://docs.puppetlabs.com/guides/tests_smoke.html
#
include acl

file { ['c:/tempperms',
   'c:/tempperms/minimal',
   'c:/tempperms/full',
   'c:/tempperms/multiuser',
   'c:/tempperms/protected',
   'c:/tempperms/protected_purge',
   'c:/tempperms/inheritance',
   'c:/tempperms/propagation',
   'c:/tempperms/deny',
   'c:/tempperms/same_user',
   'c:/tempperms/rights_ordering',
   'c:/tempperms/identities']:
  ensure => directory,
}

acl { 'c:/tempperms/minimal':
  ensure      => present,
  permissions => [
   { identity => 'Administrator', rights => ['full'] }
 ],
}

#C:\tempperms>icacls minimal
#minimal WIN-QR952GIDHVE\Administrator:(OI)(CI)(F)
#        BUILTIN\Administrators:(I)(F)
#        BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
#        NT AUTHORITY\SYSTEM:(I)(F)
#        NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
#        BUILTIN\Users:(I)(OI)(CI)(RX)
#        NT AUTHORITY\Authenticated Users:(I)(M)
#        NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)


# same as minimal but fully expressed
acl { 'c:/tempperms/full':
  ensure      => present,
  target      => 'c:/tempperms/full',
  target_type => 'file',
  purge       => 'false',
  permissions => [
   { identity => 'Administrator', rights => ['full'], type=> 'allow', child_types => 'all', affects => 'all' }
  ],
  owner       => 'Administrators',
  group       => 'Users',
  inherit_parent_permissions => 'true',
}

#C:\tempperms>icacls full
#full WIN-QR952GIDHVE\Administrator:(OI)(CI)(F)
#     BUILTIN\Administrators:(I)(F)
#     BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
#     NT AUTHORITY\SYSTEM:(I)(F)
#     NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
#     BUILTIN\Users:(I)(OI)(CI)(RX)
#     NT AUTHORITY\Authenticated Users:(I)(M)
#     NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)


acl { 'c:/tempperms/multiuser':
  ensure      => present,
  permissions => [
   { identity => 'Administrator', rights => ['full'] },
   { identity => 'Users', rights => ['full'] },
   { identity => 'Authenticated Users', rights => ['full'] }
  ],
}

#C:\tempperms>icacls multiuser
#multiuser WIN-QR952GIDHVE\Administrator:(OI)(CI)(F)
#          BUILTIN\Users:(OI)(CI)(F)
#          NT AUTHORITY\Authenticated Users:(OI)(CI)(F)
#          BUILTIN\Administrators:(I)(F)
#          BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
#          NT AUTHORITY\SYSTEM:(I)(F)
#          NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
#          BUILTIN\Users:(I)(OI)(CI)(RX)
#          NT AUTHORITY\Authenticated Users:(I)(M)
#          NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)


acl { 'c:/tempperms/protected':
  ensure      => present,
  permissions => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Users', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
}

acl { 'tempperms_protected':
  ensure      => present,
  target      => 'c:/tempperms/protected'
  permissions => [
   { identity => 'Administrator', rights => ['modify'] }
  ],
  inherit_parent_permissions => 'false',
}

#C:\tempperms>icacls protected
#protected BUILTIN\Administrators:(OI)(CI)(F)
#          BUILTIN\Users:(OI)(CI)(F)
#          BUILTIN\Administrators:(F)
#          BUILTIN\Administrators:(OI)(CI)(IO)(F)
#          WIN-QR952GIDHVE\Administrator:(OI)(CI)(IO)(F)
#          NT AUTHORITY\SYSTEM:(F)
#          NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
#          NT AUTHORITY\Authenticated Users:(M)
#          NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)


acl { 'c:/tempperms/protected_purge':
  ensure      => present,
  purge       => 'true',
  permissions => [
   { identity => 'Administrators', rights => ['full'] },
   { identity => 'Users', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
}

#C:\tempperms>icacls protected_purge
#protected_purge BUILTIN\Administrators:(OI)(CI)(F)
#                BUILTIN\Users:(OI)(CI)(F)


acl { 'c:/tempperms/inheritance':
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

#C:\tempperms>icacls inheritance
#inheritance BUILTIN\Administrators:(CI)(F)
#            WIN-QR952GIDHVE\Administrator:(OI)(F)
#            BUILTIN\Users:(F)


acl { 'c:/tempperms/propagation':
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

#C:\tempperms>icacls propagation
#propagation BUILTIN\Administrators:(OI)(CI)(M)
#            BUILTIN\Administrators:(F)
#            WIN-QR952GIDHVE\Administrator:(OI)(CI)(NP)(IO)(F)
#            BUILTIN\Users:(OI)(CI)(IO)(F)
#            NT AUTHORITY\Authenticated Users:(OI)(CI)(NP)(R)

file { ['c:/tempperms/propagation/child_container',
   'c:/tempperms/propagation/child_container/grandchild_container']:
  ensure => 'directory',
}

#C:\tempperms\propagation>icacls child_container
#child_container BUILTIN\Administrators:(I)(OI)(CI)(M)
#                WIN-QR952GIDHVE\Administrator:(I)(F)
#                BUILTIN\Users:(I)(OI)(CI)(F)
#                NT AUTHORITY\Authenticated Users:(I)(R)

#C:\tempperms\propagation\child_container>icacls grandchild_container
#grandchild_container BUILTIN\Administrators:(I)(OI)(CI)(M)
#                     BUILTIN\Users:(I)(OI)(CI)(F)

file { ['c:/tempperms/propagation/child_object.txt',
   'c:/tempperms/propagation/child_container/grandchild_object.txt']:
  ensure  => 'file',
  content => 'what',
}

#C:\tempperms\propagation>icacls child_object.txt
#child_object.txt BUILTIN\Administrators:(I)(M)
#                 WIN-QR952GIDHVE\Administrator:(I)(F)
#                 BUILTIN\Users:(I)(F)
#                 NT AUTHORITY\Authenticated Users:(I)(R)

#C:\tempperms\propagation\child_container>icacls grandchild_object.txt
#grandchild_object.txt BUILTIN\Administrators:(I)(M)
#                      BUILTIN\Users:(I)(F)


acl { 'c:/tempperms/deny':
  ensure      => present,
  permissions => [
   { identity => 'SYSTEM', rights => ['full'], type=> 'deny' }
  ],
}

# BUG: Deny does not inherit by default?

#C:\tempperms>icacls deny
#deny  NT AUTHORITY\SYSTEM:(N)
#      BUILTIN\Administrators:(I)(F)
#      BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
#      NT AUTHORITY\SYSTEM:(I)(F)
#      NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
#      BUILTIN\Users:(I)(OI)(CI)(RX)
#      NT AUTHORITY\Authenticated Users:(I)(M)
#      NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)


acl { 'c:/tempperms/same_user':
  ensure      => present,
  purge       => 'true',
  permissions => [
   #{ identity => 'SYSTEM', rights => ['modify'], type=> 'deny', child_types => 'none' },
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

#C:\tempperms>icacls same_user
#same_user NT AUTHORITY\SYSTEM:(DENY)(M)
#          NT AUTHORITY\SYSTEM:(M)
#          NT AUTHORITY\SYSTEM:(CI)(M)
#          NT AUTHORITY\SYSTEM:(OI)(M)
#          NT AUTHORITY\SYSTEM:(F)
#          NT AUTHORITY\SYSTEM:(OI)(CI)(NP)(IO)(RX)
#          NT AUTHORITY\SYSTEM:(CI)(NP)(IO)(RX)
#          NT AUTHORITY\SYSTEM:(OI)(NP)(IO)(RX)
#          NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
#          NT AUTHORITY\SYSTEM:(CI)(IO)(F)
#          NT AUTHORITY\SYSTEM:(OI)(IO)(F)
#          NT AUTHORITY\SYSTEM:(OI)(CI)(NP)(R)
#          NT AUTHORITY\SYSTEM:(CI)(NP)(R)
#          NT AUTHORITY\SYSTEM:(OI)(NP)(R)


acl { 'c:/tempperms/rights_ordering':
  ensure      => present,
  purge       => 'true',
  permissions => [
   { identity => 'SYSTEM', rights => ['execute','read'] },
   { identity => 'SYSTEM', rights => ['read','read'], affects => 'direct_children_only' },
   { identity => 'Administrators', rights => ['full','modify'] },
   { identity => 'Administrator', rights => ['modify','read'] }
  ],
  inherit_parent_permissions => 'false',
}

#this will issue warnings - expected
#C:\tempperms>icacls rights_ordering
#rights_ordering NT AUTHORITY\SYSTEM:(OI)(CI)(RX)
#                NT AUTHORITY\SYSTEM:(OI)(CI)(NP)(IO)(R)
#                BUILTIN\Administrators:(OI)(CI)(F)
#                WIN-QR952GIDHVE\Administrator:(OI)(CI)(M)


acl { 'c:/tempperms/identities':
  ensure      => present,
  purge       => 'true',
  permissions => [
   { identity => 'NT AUTHORITY\SYSTEM', rights => ['modify'] },
   { identity => 'BUILTIN\Users', rights => ['read','execute'] },
   { identity => 'S-1-5-32-544', rights => ['full'] }
  ],
  inherit_parent_permissions => 'false',
}

#C:\tempperms>icacls identities
#identities NT AUTHORITY\SYSTEM:(OI)(CI)(M)
#           BUILTIN\Users:(OI)(CI)(RX)
#           BUILTIN\Administrators:(OI)(CI)(F)
