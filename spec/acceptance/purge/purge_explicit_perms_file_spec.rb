require 'spec_helper_acceptance'

describe 'Purge' do
  let(:acl_manifest) do
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

  let(:purge_acl_manifest) do
    <<-MANIFEST
      acl { "#{target}":
        purge        => 'true',
        permissions  => [
          { identity => '#{user_id2}', rights => ['full'] },
        ]
      }
    MANIFEST
  end

  context 'Negative- Only Purge Explicit Permissions from File with Inheritance' do
    random_username = generate_random_username

    let(:target) { "#{target_parent}/purge_exp_inherit.txt" }
    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }

    let(:file_content) { 'Surge Purge Merge' }
    let(:verify_content_path) { target }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:acl_regex_user_id1) { %r{.*\\bob:\(F\)} }
    let(:acl_regex_user_id2) { %r{.*\\#{user_id2}:\(F\)} }

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'applies manifest' do
          execute_manifest_on(agent, acl_manifest, debug: true) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'verifies ACL rights' do
          on(agent, verify_acl_command) do |result|
            expect(result.stdout).to match(%r{#{acl_regex_user_id1}})
          end
        end

        it 'executes purge' do
          execute_manifest_on(agent, purge_acl_manifest, debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'verifies ACL rights (post-purge)' do
          on(agent, verify_acl_command) do |result|
            expect(result.stdout).not_to match(%r{#{acl_regex_user_id1}})
            expect(result.stdout).to match(%r{#{acl_regex_user_id2}})
          end
        end

        it 'verifies file data integrity' do
          expect(file(verify_content_path)).to be_file
          expect(file(verify_content_path).content).to match(%r{#{file_content}})
        end
      end
    end
  end
end
