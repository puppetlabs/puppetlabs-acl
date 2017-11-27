test_name 'Windows ACL Module - Negative - Set Propagation on a File'

confine(:to, :platform => 'windows')

#Globals
rights = 'full'
prop_type = 'all'
affects_child_type = 'all'
file_content = 'Flying beavers attack Lake Oswego!'

parent_name = 'temp'
target_name = "prop_file"

target_parent = "c:/#{parent_name}"
target = "#{target_parent}/#{target_name}"
user_id = 'bob'

verify_content_command = "cat /cygdrive/c/#{parent_name}/#{target_name}"
file_content_regex = /\A#{file_content}\z/

# 4c734680aca3b3781ae9fb211759a5610c6679a8 changed how permissions are emitted
# during a `puppet agent` / `puppet apply` (but not `puppet resource`), so that
# instead of emitting a [Puppet::Type::Acl::Ace] for rendering to the console
# a [Hash] is emitted in the permissions_to_s method
# Puppet 4 and 5 have different behavior for rendering this data structure
verify_manifest_pup4 = /\{ affects => 'self_only', identity => '.*\\bob', rights => \['full'\s+\] \}/
verify_manifest_pup5 = /\{"identity"=>".*\\bob", "rights"=>\["full"\], "affects"=>:self_only\}/

verify_acl_command = "icacls #{target}"
acl_regex = /.*\\bob:\(F\)/

#Manifests
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
  purge           => 'true',
  permissions     => [
    { identity    => '#{user_id}',
      rights      => ['#{rights}'],
      affects     => '#{prop_type}',
      child_types => '#{affects_child_type}'
    },
    { identity    => 'Administrators',
      rights      => ['full'],
      affects     => 'all',
      child_types => 'all'
    }
  ],
  inherit_parent_permissions => 'false'
}
MANIFEST

#Tests
agents.each do |agent|
  step "Detect Agent Version"
  agent_version_response = on(agent, puppet('--version')).stdout.chomp
  agent_version = Gem::Version.new(agent_version_response)

  step "Execute Apply Manifest"
  on(agent, puppet('apply', '--debug'), :stdin => acl_manifest) do |result|
    verify_manifest = (agent_version >= Gem::Version.new('5.0.0')) ?
      verify_manifest_pup5 :
      verify_manifest_pup4

    assert_match(verify_manifest, result.stdout, 'Expected ACL change event not detected!')
  end

  step "Verify that ACL Rights are Correct"
  on(agent, verify_acl_command) do |result|
    assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
  end

  step "Verify File Data Integrity"
  on(agent, verify_content_command) do |result|
    assert_match(file_content_regex, result.stdout, 'File content is invalid!')
  end
end
