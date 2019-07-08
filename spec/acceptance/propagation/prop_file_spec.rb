describe 'Propagate - Negative' do
  def acl_manifest(target_name, file_content, rights, prop_type, affects_child_type)
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
    rights = 'full'
    prop_type = 'all'
    affects_child_type = 'all'
    file_content = 'Flying beavers attack Lake Oswego!'
    target_name = 'prop_file'

    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"

    # 4c734680aca3b3781ae9fb211759a5610c6679a8 changed how permissions are emitted
    # during a `puppet agent` / `puppet apply` (but not `puppet resource`), so that
    # instead of emitting a [Puppet::Type::Acl::Ace] for rendering to the console
    # a [Hash] is emitted in the permissions_to_s method
    # Puppet 4 and 5 have different behavior for rendering this data structure
    verify_manifest_pup4 = %r{\{ affects => 'self_only', identity => '.*\\bob', rights => \['full'\s+\] \}}
    verify_manifest_pup5 = %r{\{"identity"=>".*\\bob", "rights"=>\["full"\], "affects"=>:self_only\}}

    verify_acl_command = "icacls #{target_parent}/#{target_name}"
    acl_regex = %r{.*\\bob:\(F\)}
    windows_agents.each do |agent|
      context "on #{agent}" do
        agent_version_response = on(agent, puppet('--version')).stdout.chomp
        agent_version = Gem::Version.new(agent_version_response)
        it 'Execute Apply Manifest' do
          execute_manifest_on(agent, acl_manifest(target_name, file_content, rights, prop_type, affects_child_type), debug: true) do |result|
            verify_manifest = (agent_version >= Gem::Version.new('5.0.0')) ? verify_manifest_pup5 : verify_manifest_pup4

            expect(result.stdout).to match(%r{#{verify_manifest}})
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            expect(result.stdout).to match(%r{#{acl_regex}})
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command) do |result|
            expect(result.stdout).to match(%r{#{file_content_regex(file_content)}})
          end
        end
      end
    end
  end
end
