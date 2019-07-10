require 'spec_helper_acceptance'

describe 'Use Cases' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_file}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { "#{target_parent}/#{target_file}":
        permissions  => [
          { identity => '#{user_id}',perm_type => 'allow', rights => ['full'] },
          { identity => '#{user_id}',perm_type => 'deny', rights => ['full'] }
        ],
      }
    MANIFEST
  end

  context 'Negative - Allow and Deny ACE for Single Identity in ACL' do
    let(:test_short_name) { 'allow_deny_ident' }
    let(:file_content) { 'Epic fail' }
    let(:target_file) { "use_case_#{test_short_name}.txt" }
    let(:verify_content_path) { "#{target_parent}/#{target_file}" }
    let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }
    let(:target_first_ace_regex) { %r{.*\\bob:\(F\)} }
    let(:target_second_ace_regex) { %r{.*\\bob:\(N\)} }

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'applies manifest' do
          execute_manifest_on(agent, acl_manifest, debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'verifies ACL rights' do
          on(agent, verify_acl_command) do |result|
            expect(result.stdout).to match(target_first_ace_regex)
            expect(result.stdout).to match(target_second_ace_regex)
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
