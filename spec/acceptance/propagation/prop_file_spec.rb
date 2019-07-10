require 'spec_helper_acceptance'

describe 'Propagate - Negative' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { '#{target_parent}/#{target_name}':
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

  context 'Set Propagation on a File' do
    let(:rights) { 'full' }
    let(:prop_type) { 'all' }
    let(:affects_child_type) { 'all' }
    let(:file_content) { 'Flying beavers attack Lake Oswego!' }
    let(:target_name) { 'prop_file' }

    let(:verify_content_path) { "#{target_parent}/#{target_name}" }

    # 4c734680aca3b3781ae9fb211759a5610c6679a8 changed how permissions are emitted
    # during a `puppet agent` / `puppet apply` (but not `puppet resource`), so that
    # instead of emitting a [Puppet::Type::Acl::Ace] for rendering to the console
    # a [Hash] is emitted in the permissions_to_s method
    # Puppet 4 and 5 have different behavior for rendering this data structure
    let(:verify_manifest_pup4) { %r{\{ affects => 'self_only', identity => '.*\\bob', rights => \['full'\s+\] \}} }
    let(:verify_manifest_pup5) { %r{\{"identity"=>".*\\bob", "rights"=>\["full"\], "affects"=>:self_only\}} }

    let(:verify_acl_command) { "icacls #{target_parent}/#{target_name}" }
    let(:acl_regex) { %r{.*\\bob:\(F\)} }

    let(:agent_version_response) { run_shell('puppet --version').stdout.chomp }
    let(:agent_version) { Gem::Version.new(agent_version_response) }

    include_examples 'execute manifest and verify file'
  end
end
