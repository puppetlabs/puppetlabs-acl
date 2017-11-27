test_name 'Windows ACL Module - Change Group to Local Unicode User'

confine(:to, :platform => 'windows')

#Globals
prefix = SecureRandom.uuid.to_s
file_content = 'Burning grass on a cold winter day.'

parent_name = 'temp'
target_name = "#{prefix}.txt"

target_parent = "c:/#{parent_name}"
target = "#{target_parent}/#{target_name}"
user_id = 'bob'

raw_group_id = 'group2_\u03A3\u03A4\u03A5\u03A6'
group_id =     "group2_\u03A3\u03A4\u03A5\u03A6" # ΣΤΥΦ

verify_group_command = "(Get-ACL '#{target}' | Where-Object { $_.Group -match ('.*\\\\' + [regex]::Unescape(\"#{raw_group_id}\")) } | Measure-Object).Count"

#Manifests
acl_manifest = <<-MANIFEST
file { "#{target_parent}":
  ensure => directory
}

file { "#{target}":
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

user { "#{group_id}":
  ensure     => present,
  groups     => 'Users',
  managehome => true,
  password   => "L0v3Pupp3t!"
}

acl { "#{target}":
  purge           => 'true',
  permissions     => [
    { identity    => 'CREATOR GROUP',
      rights      => ['modify']
    },
    { identity    => '#{user_id}',
      rights      => ['read']
    },
    { identity    => 'Administrators',
      rights      => ['full'],
      affects     => 'all',
      child_types => 'all'
    }
  ],
  group           => '#{group_id}',
  inherit_parent_permissions => 'false'
}
MANIFEST

#Tests
agents.each do |agent|
  step "Execute ACL Manifest"
  apply_manifest_on(agent, acl_manifest, {:debug => true}) do |result|
    assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
  end

  step "Verify that ACL Rights are Correct"
  on(agent, powershell(verify_group_command, {'EncodedCommand' => true})) do |result|
    assert_match(/^1$/, result.stdout, 'Expected ACL was not present!')
  end
end
