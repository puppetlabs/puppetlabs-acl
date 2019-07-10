require 'spec_helper_acceptance'

describe 'Use Cases' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { "first_acl":
        target       => '#{target_parent}/#{target_name}',
        permissions  => [
          { identity => '#{user_id}',perm_type => 'deny', rights => ['full'] }
        ],
      }

      acl { "second_acl":
        target       => '#{target_parent}/#{target_name}',
        permissions  => [
          { identity => '#{user_id}',perm_type => 'deny', rights => ['full'] }
        ],
      }
    MANIFEST
  end

  context 'Negative - Multiple ACL for Single Path' do
    let(:test_short_name) { 'multi_acl_single_target' }
    let(:file_content) { 'MEGA ULTRA FAIL!' }
    let(:target_name) { "use_case_#{test_short_name}.txt" }
    let(:verify_content_path) { "#{target_parent}/#{target_name}" }
    let(:verify_acl_command) { "icacls #{target_parent}/#{target_name}" }
    let(:target_first_ace_regex) { %r{.*\\bob:\(F\)} }
    let(:target_second_ace_regex) { %r{.*\\bob:\(N\)} }

    it 'applies manifest' do
      idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).not_to match(target_first_ace_regex)
        expect(result.stdout).to match(target_second_ace_regex)
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
