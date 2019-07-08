require 'spec_helper_acceptance'

def apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
  context "on #{agent}" do
    rights = 'full'
    target_name = "prop_#{prop_type}_to_#{affects_child_type}"
    verify_acl_command = "icacls #{target_parent}/#{target_name}"
    it 'Execute Apply Manifest' do
      execute_manifest_on(agent, acl_manifest(target_name, rights, prop_type, affects_child_type), debug: true) do |result|
        expect(result.stderr).not_to match(%r{Error:})
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{acl_regex}})
      end
    end
  end
end

# rubocop:disable RSpec/EmptyExampleGroup
describe 'Propagation' do
  def acl_manifest(target_name, rights, prop_type, affects_child_type)
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
        password   => "L0v3Pupp3t!"
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
    MANIFEST
  end

  context 'Propagate "all" to "all" Child Types' do
    prop_type = 'all'
    affects_child_type = 'all'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "all" to "containers" Child Types' do
    prop_type = 'all'
    affects_child_type = 'containers'
    acl_regex = %r{.*\\bob:\(CI\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "all" to "none" Child Types' do
    prop_type = 'all'
    affects_child_type = 'none'
    acl_regex = %r{.*\\bob:\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "all" to "objects" Child Types' do
    prop_type = 'all'
    affects_child_type = 'objects'
    acl_regex = %r{.*\\bob:\(OI\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "children_only" to "all" Child Types' do
    prop_type = 'children_only'
    affects_child_type = 'all'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(IO\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "children_only" to "containers" Child Types' do
    prop_type = 'children_only'
    affects_child_type = 'containers'
    acl_regex = %r{.*\\bob:\(CI\)\(IO\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "children_only" to "objects" Child Types' do
    prop_type = 'children_only'
    affects_child_type = 'objects'
    acl_regex = %r{.*\\bob:\(OI\)\(IO\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "direct_children_only" to "all" Child Types' do
    prop_type = 'direct_children_only'
    affects_child_type = 'all'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(NP\)\(IO\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "direct_children_only" to "containers" Child Types' do
    prop_type = 'direct_children_only'
    affects_child_type = 'containers'
    acl_regex = %r{.*\\bob:\(CI\)\(NP\)\(IO\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "direct_children_only" to "objects" Child Types' do
    prop_type = 'direct_children_only'
    affects_child_type = 'objects'
    acl_regex = %r{.*\\bob:\(OI\)\(NP\)\(IO\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "self_and_direct_children_only" to "all" Child Types' do
    prop_type = 'self_and_direct_children_only'
    affects_child_type = 'all'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(NP\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "self_and_direct_children_only" to "containers" Child Types' do
    prop_type = 'self_and_direct_children_only'
    affects_child_type = 'containers'
    acl_regex = %r{.*\\bob:\(CI\)\(NP\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end

  context 'Propagate "self_and_direct_children_only" to "objects" Child Types' do
    prop_type = 'self_and_direct_children_only'
    affects_child_type = 'objects'
    acl_regex = %r{.*\\bob:\(OI\)\(NP\)\(F\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(prop_type, affects_child_type, acl_regex, agent)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
