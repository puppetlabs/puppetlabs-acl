require 'spec_helper_acceptance'

describe 'Propagate' do
  let(:acl_manifest) do
    <<-MANIFEST
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

  let(:rights) { 'full' }
  let(:target_name) { "prop_#{prop_type}_to_#{affects_child_type}" }
  let(:target_child_name) { "prop_#{prop_type}_child" }
  let(:target_child) { "#{target_parent}/#{target_name}/#{target_child_name}" }

  let(:verify_acl_command) { "icacls #{target_parent}/#{target_name}" }
  let(:verify_child_acl_command) { "icacls #{target_child}" }

  context 'Negative - Propagate "self_only" to "all" Child Types' do
    let(:prop_type) { 'self_only' }
    let(:affects_child_type) { 'all' }
    let(:acl_regex) { %r{.*\\bob:\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify child', agent
    end
  end
end
