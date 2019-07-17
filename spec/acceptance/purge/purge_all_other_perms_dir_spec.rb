require 'spec_helper_acceptance'

describe 'Purge' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
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

  let(:acl_manifest_purge) do
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

  context 'Purge All Other Permissions from Directory without Inheritance' do
    random_username = generate_random_username
    let(:target) { "#{target_parent}/purge_all_other_no_inherit" }
    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:acl_regex_user_id1) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }
    let(:acl_regex_user_id2) { %r{\Ac:\/temp\/purge_all_other_no_inherit.*\\#{user_id2}:\(OI\)\(CI\)\(F\)\n\nSuccessfully} }

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'applies manifest' do
          execute_manifest_on(agent, acl_manifest, debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'verifies ACL rights' do
          on(agent, verify_acl_command) do |result|
            assert_match(acl_regex_user_id1, result.stdout, 'Expected ACL was not present!')
            expect(result.stdout).to match(%r{#{acl_regex_user_id1}})
          end
        end

        it 'executes purge' do
          execute_manifest_on(agent, acl_manifest_purge, debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'verifies ACL rights (post-purge)' do
          on(agent, verify_acl_command, acceptable_exit_codes: [0, 5]) do |result|
            expect(result.stdout).not_to match(%r{#{acl_regex_user_id1}})
            expect(result.stdout).to match(%r{#{acl_regex_user_id2}})
          end
        end
      end
    end
  end
end
