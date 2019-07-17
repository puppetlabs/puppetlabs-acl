require 'spec_helper_acceptance'

describe 'Propagation' do
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

  let(:rights) { 'full' }
  let(:target_name) { "prop_#{prop_type}_to_#{affects_child_type}" }
  let(:verify_acl_command) { "icacls #{target_parent}/#{target_name}" }

  context 'Propagate "all" to "all" Child Types' do
    let(:prop_type) { 'all' }
    let(:affects_child_type) { 'all' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "all" to "containers" Child Types' do
    let(:prop_type) { 'all' }
    let(:affects_child_type) { 'containers' }
    let(:acl_regex) { %r{.*\\bob:\(CI\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "all" to "none" Child Types' do
    let(:prop_type) { 'all' }
    let(:affects_child_type) { 'none' }
    let(:acl_regex) { %r{.*\\bob:\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "all" to "objects" Child Types' do
    let(:prop_type) { 'all' }
    let(:affects_child_type) { 'objects' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "children_only" to "all" Child Types' do
    let(:prop_type) { 'children_only' }
    let(:affects_child_type) { 'all' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(IO\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "children_only" to "containers" Child Types' do
    let(:prop_type) { 'children_only' }
    let(:affects_child_type) { 'containers' }
    let(:acl_regex) { %r{.*\\bob:\(CI\)\(IO\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "children_only" to "objects" Child Types' do
    let(:prop_type) { 'children_only' }
    let(:affects_child_type) { 'objects' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(IO\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "direct_children_only" to "all" Child Types' do
    let(:prop_type) { 'direct_children_only' }
    let(:affects_child_type) { 'all' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(NP\)\(IO\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "direct_children_only" to "containers" Child Types' do
    let(:prop_type) { 'direct_children_only' }
    let(:affects_child_type) { 'containers' }
    let(:acl_regex) { %r{.*\\bob:\(CI\)\(NP\)\(IO\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "direct_children_only" to "objects" Child Types' do
    let(:prop_type) { 'direct_children_only' }
    let(:affects_child_type) { 'objects' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(NP\)\(IO\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "self_and_direct_children_only" to "all" Child Types' do
    let(:prop_type) { 'self_and_direct_children_only' }
    let(:affects_child_type) { 'all' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(NP\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "self_and_direct_children_only" to "containers" Child Types' do
    let(:prop_type) { 'self_and_direct_children_only' }
    let(:affects_child_type) { 'containers' }
    let(:acl_regex) { %r{.*\\bob:\(CI\)\(NP\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context 'Propagate "self_and_direct_children_only" to "objects" Child Types' do
    let(:prop_type) { 'self_and_direct_children_only' }
    let(:affects_child_type) { 'objects' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(NP\)\(F\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end
end
