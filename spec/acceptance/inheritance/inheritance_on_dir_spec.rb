require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, agent)
  rights = 'full'
  user_id_child = 'roberto'
  target_name = "inherit_#{perm_type}_on_#{asset_type}"
  target_child_name = "child_#{asset_type}"
  target_child = "#{target_parent}/#{target_name}/#{target_child_name}"

  context "on #{agent}" do
    it 'Execute Apply Manifest' do
      execute_manifest_on(agent, acl_manifest(target_name, target_child, user_id_child, rights, perm_type, child_inherit_type), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct on Child' do
      on(agent, verify_child_acl_command(target_child)) do |result|
        assert_match(acl_child_regex, result.stdout, 'Expected ACL was not present!')
      end
    end
  end
end

describe 'Inheritance - Directory' do
  def acl_manifest(target_name, target_child, user_id_child, rights, perm_type, child_inherit_type)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      file { "#{target_child}":
        ensure  => directory,
        require => File['#{target_parent}/#{target_name}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id_child}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target_parent}/#{target_name}":
        purge        => 'true',
        permissions  => [
          { identity  => '#{user_id}',
            rights    => ['#{rights}'],
            perm_type => '#{perm_type}'
          },
          { identity => 'Administrators',
            rights   => ['full']
          }
        ],
        inherit_parent_permissions => 'false'
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity  => '#{user_id_child}',
            rights    => ['#{rights}'],
            perm_type => '#{perm_type}'
          }
        ],
        inherit_parent_permissions => '#{child_inherit_type}'
      }
    MANIFEST
  end

  def verify_child_acl_command(target_child)
    "icacls #{target_child}"
  end

  context 'Explicit Inheritance of "allow" Parent Permissions for Directory' do
    perm_type = 'allow'
    asset_type = 'dir'
    child_inherit_type = 'true'
    acl_child_regex = %r{.*\\bob:\(I\)\(OI\)\(CI\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, agent)
    end
  end

  context 'Explicit Inheritance of "deny" Parent Permissions for Directory' do
    perm_type = 'deny'
    asset_type = 'dir'
    child_inherit_type = 'true'
    acl_child_regex = %r{.*\\bob:\(I\)\(OI\)\(CI\)\(N\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, agent)
    end
  end

  context 'Remove Inheritance of "allow" Parent Permissions for Directory' do
    perm_type = 'allow'
    asset_type = 'dir'
    child_inherit_type = 'false'
    acl_child_regex = %r{.*\\bob:\(OI\)\(CI\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, agent)
    end
  end

  context 'Remove Inheritance of "deny" Parent Permissions for Directory' do
    perm_type = 'deny'
    asset_type = 'dir'
    child_inherit_type = 'false'
    acl_child_regex = %r{.*\\bob:\(OI\)\(CI\)\(N\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, agent)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
