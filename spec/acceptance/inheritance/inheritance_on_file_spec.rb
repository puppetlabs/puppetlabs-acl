require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, file_content, agent)
  rights = 'full'
  user_id_child = 'roberto'
  target_name = "inherit_#{perm_type}_on_#{asset_type}"
  target_child_name = "child_#{asset_type}"
  target_child = "#{target_parent}/#{target_name}/#{target_child_name}"

  context "on #{agent}" do
    it 'Execute Apply Manifest' do
      execute_manifest_on(agent, acl_manifest(target_name, target_child, file_content, user_id_child, rights, perm_type, child_inherit_type), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct on Child' do
      on(agent, verify_child_acl_command(target_child)) do |result|
        assert_match(acl_child_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command(target_name, target_child_name)) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'Inheritance' do
  def acl_manifest(target_name, target_child, file_content, user_id_child, rights, perm_type, child_inherit_type)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      file { "#{target_child}":
        ensure  => file,
        content => '#{file_content}',
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

  def verify_content_command(target_name, target_child_name)
    "cat /cygdrive/c/temp/#{target_name}/#{target_child_name}"
  end

  context 'Explicit Inheritance of "allow" Parent Permissions for File' do
    perm_type = 'allow'
    asset_type = 'file'
    child_inherit_type = 'true'
    file_content = 'Car repair is expensive'
    acl_child_regex = %r{.*\\bob:\(I\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, file_content, agent)
    end
  end

  context 'Explicit Inheritance of "deny" Parent Permissions for File' do
    perm_type = 'deny'
    asset_type = 'file'
    child_inherit_type = 'true'
    file_content = 'Exploding pants on sale for half off.'
    acl_child_regex = %r{.*\\bob:\(I\)\(N\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, file_content, agent)
    end
  end

  context 'Remove Inheritance of "allow" Parent Permissions for File' do
    perm_type = 'allow'
    asset_type = 'file'
    child_inherit_type = 'false'
    file_content = 'Smell-o-vision: brought to you by the makers of Taste-o-vision!'
    acl_child_regex = %r{.*\\bob:\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, file_content, agent)
    end
  end

  context 'Remove Inheritance of "deny" Parent Permissions for File' do
    perm_type = 'deny'
    asset_type = 'file'
    child_inherit_type = 'false'
    file_content = 'She smirked as he disdainfully choked down her tasteless humor.'
    acl_child_regex = %r{.*\\bob:\(N\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(perm_type, asset_type, child_inherit_type, acl_child_regex, file_content, agent)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
