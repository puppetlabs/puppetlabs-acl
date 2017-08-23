test_name 'Windows ACL Module - Add Permissions to a Unicode File'

confine(:to, :platform => 'windows')

#Globals
target_parent = 'c:/temp'
filename = "unicode_file_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt"
target = "c:/temp/#{filename}"
user_id = 'bob'

file_content = 'Puppets and Muppets! Cats on the Interwebs!'
verify_content_command = 'powershell.exe -command "Get-ChildItem c:\\temp\\* -File | % { \\$_.PSChildName, (Get-Content \\$_) }"'
file_content_regex = /^#{filename}\n#{file_content}$/m

# ensure bob has Full rights
verify_acl_command = "powershell.exe -command \"Get-Acl C:\\temp\\*.* | ? { \\$_.Access | ? { \\$_.IdentityReference -match '\\\\\\#{user_id}' -and \\$_.FileSystemRights -eq 'FullControl' } } | Select -ExpandProperty PSChildName\""

#Manifest
acl_manifest = <<-MANIFEST
file { "#{target_parent}":
  ensure => directory
}

file { '#{target}':
  ensure  => file,
  content => '#{file_content}',
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
  on(agent, verify_acl_command) do |result|
    assert_match(/^#{filename}$/, result.stdout, 'Expected ACL was not present!')
  end

  step "Verify File Data Integrity"
  on(agent, verify_content_command) do |result|
    assert_match(file_content_regex, result.stdout, 'Expected file content is invalid!')
  end
end
