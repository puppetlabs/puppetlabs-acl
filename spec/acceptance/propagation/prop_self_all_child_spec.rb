require 'spec_helper_acceptance'

def apply_manifest_and_verify(acl_regex, agent, prop_type, affects_child_type)
  context "on #{agent}" do
    rights = 'full'
    target_name = "prop_#{prop_type}_to_#{affects_child_type}"
    target_child_name = "prop_#{prop_type}_child"
    target_child = "#{target_parent}/#{target_name}/#{target_child_name}"

    verify_acl_command = "icacls #{target_parent}/#{target_name}"
    verify_child_acl_command = "icacls #{target_child}"

    it 'Execute Apply Manifest' do
      on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target_name, rights, prop_type, target_child, affects_child_type)) do |result|
        assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify that ACL Rights are Correct on Child' do
      on(agent, verify_child_acl_command) do |result|
        assert_no_match(acl_regex, result.stdout, 'Unexpected ACL was present!')
      end
    end
  end
end

describe 'Propagate' do

  def acl_manifest(target_name, rights, prop_type, target_child, affects_child_type)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target_parent}/#{target_name}":
        ensure  => directory,
        require => File['#{target_parent}']
      }
      
      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!",
      }
      
      acl { "#{target_parent}/#{target_name}":
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
      ->
      file { "#{target_child}":
        ensure  => directory
      }
    MANIFEST
  end

  context 'Negative - Propagate "self_only" to "all" Child Types' do
    prop_type = 'self_only'
    affects_child_type = 'all'
    acl_regex = /.*\\bob:\(F\)/
    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, prop_type, affects_child_type)
    end
  end
end
