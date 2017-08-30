test_name 'Windows ACL Module - Add Permissions to a Unicode File'

confine(:to, :platform => 'windows')

#Globals
target_parent = 'c:/temp'
prefix = SecureRandom.uuid.to_s
raw_filename = prefix + '_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt'
filename     = "#{prefix}_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt"
target = "#{target_parent}/#{filename}"
user_id = 'bob'

file_content = 'Puppets and Muppets! Cats on the Interwebs!'

# ensure bob has Full rights
verify_acl_command = "(Get-Acl ('#{target_parent}/' + [regex]::Unescape(\"#{raw_filename}\")) | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match '\\\\#{user_id}' -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count"

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
  apply_manifest_on(agent, acl_manifest, {:debug => true}) do |result|
      assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
  end

  step "Verify that ACL Rights are Correct"
  on(agent, powershell(verify_acl_command, {'EncodedCommand' => true})) do |result|
    assert_match(/^1$/, result.stdout, 'Expected ACL was not present!')
  end
end
