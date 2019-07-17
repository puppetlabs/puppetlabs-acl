require 'spec_helper_acceptance'

describe 'Inheritance - Directory' do
  let(:rights) { 'full' }
  let(:user_id_child) { 'roberto' }
  let(:target_name) { "inherit_#{perm_type}_on_#{asset_type}" }
  let(:target_child_name) { "child_#{asset_type}" }
  let(:target_child) { "#{target_parent}/#{target_name}/#{target_child_name}" }

  let(:acl_manifest) do
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

  let(:verify_acl_command) { "icacls #{target_child}" }
  let(:verify_content_path) { "#{target_parent}/#{target_name}" }

  context 'Explicit Inheritance of "allow" Parent Permissions for Directory' do
    let(:perm_type) { 'allow' }
    let(:asset_type) { 'dir' }
    let(:child_inherit_type) { 'true' }
    let(:acl_regex) { %r{.*\\bob:\(I\)\(OI\)\(CI\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Explicit Inheritance of "deny" Parent Permissions for Directory' do
    let(:perm_type) { 'deny' }
    let(:asset_type) { 'dir' }
    let(:child_inherit_type) { 'true' }
    let(:acl_regex) { %r{.*\\bob:\(I\)\(OI\)\(CI\)\(N\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Remove Inheritance of "allow" Parent Permissions for Directory' do
    let(:perm_type) { 'allow' }
    let(:asset_type) { 'dir' }
    let(:child_inherit_type) { 'false' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Remove Inheritance of "deny" Parent Permissions for Directory' do
    let(:perm_type) { 'deny' }
    let(:asset_type) { 'dir' }
    let(:child_inherit_type) { 'false' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(N\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end
end
