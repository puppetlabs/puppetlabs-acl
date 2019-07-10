require 'spec_helper_acceptance'

describe 'Inheritance' do
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

  let(:verify_acl_command) { "icacls #{target_child}" }
  let(:verify_content_path) { "c:\\temp\\#{target_name}\\#{target_child_name}" }

  context 'Explicit Inheritance of "allow" Parent Permissions for File' do
    let(:perm_type) { 'allow' }
    let(:asset_type) { 'file' }
    let(:child_inherit_type) { 'true' }
    let(:file_content) { 'Car repair is expensive' }
    let(:acl_regex) { %r{.*\\bob:\(I\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Explicit Inheritance of "deny" Parent Permissions for File' do
    let(:perm_type) { 'deny' }
    let(:asset_type) { 'file' }
    let(:child_inherit_type) { 'true' }
    let(:file_content) { 'Exploding pants on sale for half off.' }
    let(:acl_regex) { %r{.*\\bob:\(I\)\(N\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Remove Inheritance of "allow" Parent Permissions for File' do
    let(:perm_type) { 'allow' }
    let(:asset_type) { 'file' }
    let(:child_inherit_type) { 'false' }
    let(:file_content) { 'Smell-o-vision: brought to you by the makers of Taste-o-vision!' }
    let(:acl_regex) { %r{.*\\bob:\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Remove Inheritance of "deny" Parent Permissions for File' do
    let(:perm_type) { 'deny' }
    let(:asset_type) { 'file' }
    let(:child_inherit_type) { 'false' }
    let(:file_content) { 'She smirked as he disdainfully choked down her tasteless humor.' }
    let(:acl_regex) { %r{.*\\bob:\(N\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end
end
