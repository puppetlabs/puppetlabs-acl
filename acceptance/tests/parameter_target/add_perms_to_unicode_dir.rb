test_name 'Windows ACL Module - Add Permissions to a Unicode Directory'

confine(:to, :platform => 'windows')

#Globals
target_parent = 'c:/temp'
dirname = "unicode_dir_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158"
target = "c:/temp/#{dirname}"
user_id = 'bob'

# ensure bob has Full rights with object and container inherit set
verify_acl_command = "\"Get-Acl C:\\temp\\unicode_dir_* | ? { \\$_.Access | ? { \\$_.IdentityReference -match '\\\\\\bob' -and \\$_.FileSystemRights -eq 'FullControl' -and \\$_.InheritanceFlags -eq 'ContainerInherit, ObjectInherit' } } | Select -ExpandProperty PSChildName\""

#Manifest
acl_manifest = <<-MANIFEST
file { "#{target_parent}":
  ensure => directory
}

file { "#{target}":
  ensure  => directory,
  require => File['#{target_parent}']
}

user { "#{user_id}":
  ensure     => present,
  groups     => 'Users',
  managehome => true,
  password   => "L0v3Pupp3t!"
}

acl { "#{target}":
  permissions => [
    { identity => '#{user_id}', rights => ['full'] },
  ],
}
MANIFEST

#Tests
agents.each do |agent|
  step "Execute Manifest"
  on(agent, puppet('apply', '--debug'), :stdin => acl_manifest) do |result|
    assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
  end

  step "Verify that ACL Rights are Correct"
  on(agent, powershell(verify_acl_command)) do |result|
    assert_match(/^#{dirname}$/, result.stdout, 'Expected ACL was not present!')
  end
end
