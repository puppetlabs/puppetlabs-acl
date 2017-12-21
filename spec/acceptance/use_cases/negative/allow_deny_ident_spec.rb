require 'spec_helper_acceptance'

describe 'Use Cases' do

  def acl_manifest(target, file_content)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }
      
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id}',perm_type => 'allow', rights => ['full'] },
          { identity => '#{user_id}',perm_type => 'deny', rights => ['full'] }
        ],
      }
    MANIFEST
  end

  context 'Negative - Allow and Deny ACE for Single Identity in ACL' do
    test_short_name = 'allow_deny_ident'
    file_content = 'Epic fail'
    target_name = "use_case_#{test_short_name}.txt"
    target = "#{target_parent}/#{target_name}"
    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"
    verify_acl_command = "icacls #{target}"
    target_first_ace_regex = /.*\\bob:\(F\)/
    target_second_ace_regex = /.*\\bob:\(N\)/

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target, file_content)) do |result|
            assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            assert_match(target_first_ace_regex, result.stdout, 'Expected ACL was not present!')
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
end
