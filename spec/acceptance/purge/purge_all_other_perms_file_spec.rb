require 'spec_helper_acceptance'

describe 'Purge' do
  def acl_manifest(target, file_content, user_id1, user_id2)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { "#{user_id1}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id2}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id1}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def purge_acl_manifest(target, user_id2)
    <<-MANIFEST
      acl { "#{target}":
        purge        => 'true',
        permissions  => [
          { identity => '#{user_id2}', rights => ['full'] },
        ],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  context 'Purge All Other Permissions from File without Inheritance' do
    target = "#{target_parent}/purge_all_other_no_inherit.txt"
    user_id1 = 'bob'
    user_id2 = generate_random_username

    file_content = 'All your base are belong to us.'

    verify_acl_command = "icacls #{target}"
    acl_regex_user_id1 = %r{.*\\bob:\(F\)}

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute Apply Manifest' do
          execute_manifest_on(agent, acl_manifest(target, file_content, user_id1, user_id2), debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            expect(result.stdout).to match(%r{#{acl_regex_user_id1}})
          end
        end

        it 'Execute Purge Manifest' do
          execute_manifest_on(agent, purge_acl_manifest(target, user_id2), debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end
      end
    end
  end
end
