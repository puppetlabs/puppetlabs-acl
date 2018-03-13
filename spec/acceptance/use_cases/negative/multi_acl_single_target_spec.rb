require 'spec_helper_acceptance'

describe 'Use Cases' do
  def acl_manifest(target, file_content)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { "first_acl":
        target       => '#{target}',
        permissions  => [
          { identity => '#{user_id}',perm_type => 'deny', rights => ['full'] }
        ],
      }

      acl { "second_acl":
        target       => '#{target}',
        permissions  => [
          { identity => '#{user_id}',perm_type => 'deny', rights => ['full'] }
        ],
      }
    MANIFEST
  end

  context 'Negative - Multiple ACL for Single Path' do
    test_short_name = 'multi_acl_single_target'
    file_content = 'MEGA ULTRA FAIL!'
    target_name = "use_case_#{test_short_name}.txt"
    target = "#{target_parent}/#{target_name}"

    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"

    verify_acl_command = "icacls #{target}"
    target_first_ace_regex = %r{.*\\bob:\(F\)}
    target_second_ace_regex = %r{.*\\bob:\(N\)}

    windows_agents.each do |agent|
      it 'Execute ACL Manifest' do
        on(agent, puppet('apply', '--debug'), stdin: acl_manifest(target, file_content)) do |result|
          assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          assert_no_match(target_first_ace_regex, result.stdout, 'Expected ACL was not present!')
          assert_match(target_second_ace_regex, result.stdout, 'Expected ACL was not present!')
        end
      end

      it 'Verify File Data Integrity' do
        on(agent, verify_content_command) do |result|
          assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
        end
      end
    end
  end
end
